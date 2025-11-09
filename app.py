from flask import Flask, render_template, request, jsonify, Response, flash, redirect, url_for, session
from models import db, User, Expense, Category
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import io
import csv
from flask_wtf.csrf import CSRFProtect
from flask_cors import CORS
from functools import wraps
from flask import make_response
from sqlalchemy import and_, or_, func, extract

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mishthygupta'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_PERMANENT'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_PERMANENT'] = False

CORS(app)
csrf = CSRFProtect(app)

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_page'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def no_cache(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        response = make_response(f(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    return decorated_function

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login_page'))

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        session.permanent = False
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'login_success')
            return redirect(url_for('dashboard'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register_page():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return render_template('register.html')
        new_user = User(username=username, password=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login_page'))
    return render_template('register.html')

@app.route('/api/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password = generate_password_hash(request.json.get('password'))
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists'}), 400
    new_user = User(username=username, password=password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'Registration Successful'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    user = User.query.filter_by(username=request.json.get('username')).first()
    if user and check_password_hash(user.password, request.json.get('password')):
        login_user(user)
        return jsonify({'message': 'Login Successful', 'user_id': user.id}), 200
    return jsonify({'error': 'Invalid username or password'}), 401

@app.route('/dashboard')
@login_required
@no_cache
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/dashboard', methods=['GET'])
@login_required
def dashboard_data():
    try:
        today = datetime.today()
        current_month = today.strftime('%Y-%m')
        
        expenses = Expense.query.filter_by(user_id=current_user.id).order_by(Expense.date.desc()).all()
        
        
        category_totals = {}
        for exp in expenses:
            cat_name = exp.category.name if exp.category else 'Uncategorized'
            if cat_name not in category_totals:
                category_totals[cat_name] = 0
            category_totals[cat_name] += exp.amount
        
        monthly_total = sum(exp.amount for exp in expenses if exp.date.startswith(current_month))
        
        # monthly trends for the last 6 months
        monthly_trends = []
        labels = []
        for i in range(5, -1, -1):
            
            year = today.year
            month = today.month - i
            
            # year rollover(new thing i added)
            while month <= 0:
                month += 12
                year -= 1
            
            month_date = datetime(year, month, 1)
            month_str = month_date.strftime('%Y-%m')
            month_name = month_date.strftime('%b %Y')
            labels.append(month_name)
            
            # Calculate total for this month
            total = sum(exp.amount for exp in expenses if exp.date.startswith(month_str))
            monthly_trends.append(total)
        
        # suggestions
        suggestions = []
        categories = Category.query.all()
        
        for cat in categories:
            if cat.budget:
                cat_total = category_totals.get(cat.name, 0)
                if cat_total > cat.budget:
                    suggestions.append(f" Spending in {cat.name} (₹{cat_total:.2f}) exceeds budget (₹{cat.budget:.2f})!")
                elif cat_total > cat.budget * 0.8:
                    suggestions.append(f" Spending in {cat.name} (₹{cat_total:.2f}) is nearing budget (₹{cat.budget:.2f}).")
        
        
        if not suggestions and category_totals:
            max_cat = max(category_totals, key=category_totals.get)
            max_amt = category_totals[max_cat]
            if max_amt > 5000:
                suggestions.append(f" You spent ₹{max_amt:.2f} on {max_cat}. Consider tracking this category more closely.")
            elif monthly_total > 15000:
                suggestions.append(f" Your monthly spending is ₹{monthly_total:.2f}. Consider setting up category budgets.")
            else:
                suggestions.append(' Your spending patterns look healthy. Keep it up!')
        
        expense_data = []
        for exp in expenses:
            expense_data.append({
                'id': exp.id,
                'title': exp.title,
                'amount': float(exp.amount),
                'category': exp.category.name if exp.category else 'Uncategorized',
                'date': exp.date
            })
        
        # filter dropdown part and its setup
        all_categories = list(set([exp['category'] for exp in expense_data]))
        all_categories.sort()
        
        return jsonify({
            'username': current_user.username,
            'expenses': expense_data,
            'categories': list(category_totals.keys()),
            'totals': list(category_totals.values()),
            'suggestions': suggestions,
            'monthly_total': float(monthly_total),
            'monthly_trends': monthly_trends,
            'trend_labels': labels,
            'current_month': today.strftime('%B %Y'),
            'income': float(current_user.income) if current_user.income else 0,
            'all_categories': all_categories
        })
    
    except Exception as e:
        print(f"Dashboard error: {e}")
        return jsonify({'error': 'Failed to load dashboard data'}), 500

@app.route('/add', methods=['GET', 'POST'])
@login_required
@no_cache
def add_expense_page():
    if request.method == 'POST':
        title = request.form.get('title')
        amount = request.form.get('amount')
        date = request.form.get('date')
        category_id = request.form.get('category_id')
        
        if not title or not amount or not date:
            flash('All fields are required', 'danger')
            categories = Category.query.all()
            return render_template('add_expenses.html', categories=categories)
        
        try:
            amount = float(amount)
            if amount <= 0:
                flash('Amount must be positive', 'danger')
                categories = Category.query.all()
                return render_template('add_expenses.html', categories=categories)
        except ValueError:
            flash('Invalid amount format', 'danger')
            categories = Category.query.all()
            return render_template('add_expenses.html', categories=categories)
        
        new_expense = Expense(
            title=title, 
            amount=amount, 
            date=date, 
            user_id=current_user.id, 
            category_id=int(category_id) if category_id else None
        )
        db.session.add(new_expense)
        db.session.commit()
        flash('Expense added successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    categories = Category.query.all()
    return render_template('add_expenses.html', categories=categories)

@app.route('/api/expenses', methods=['POST'])
@login_required
def add_expense():
    try:
        title = request.json.get('title')
        amount = request.json.get('amount')
        date = request.json.get('date')
        category_id = request.json.get('category_id')
        
        if not title or not amount or not date:
            return jsonify({'error': 'Title, amount, and date are required'}), 400
        
        try:
            amount = float(amount)
            if amount <= 0:
                return jsonify({'error': 'Amount must be positive'}), 400
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid amount format'}), 400
        
        new_expense = Expense(
            title=title, 
            amount=amount, 
            date=date, 
            user_id=current_user.id, 
            category_id=int(category_id) if category_id else None
        )
        db.session.add(new_expense)
        db.session.commit()
        return jsonify({'message': 'Expense added', 'id': new_expense.id}), 201
    
    except Exception as e:
        print(f"Add expense error: {e}")
        return jsonify({'error': 'Failed to add expense'}), 500

@app.route('/api/expenses/<int:id>', methods=['PUT'])
@login_required
def edit_expense_api(id):
    try:
        expense = Expense.query.get_or_404(id)
        if expense.user_id != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        title = request.json.get('title')
        amount = request.json.get('amount')
        date = request.json.get('date')
        category_id = request.json.get('category_id')
        
        if not title or not amount or not date:
            return jsonify({'error': 'Title, amount, and date are required'}), 400
        
        try:
            amount = float(amount)
            if amount <= 0:
                return jsonify({'error': 'Amount must be positive'}), 400
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid amount format'}), 400
        
        expense.title = title
        expense.amount = amount
        expense.date = date
        expense.category_id = int(category_id) if category_id else None
        db.session.commit()
        
        return jsonify({'message': 'Expense updated'}), 200
    
    except Exception as e:
        print(f"Edit expense error: {e}")
        return jsonify({'error': 'Failed to update expense'}), 500

@app.route('/api/expenses/<int:id>', methods=['DELETE'])
@login_required
def delete_expense(id):
    try:
        expense = Expense.query.get_or_404(id)
        if expense.user_id != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        db.session.delete(expense)
        db.session.commit()
        return jsonify({'message': 'Expense deleted'}), 200
    
    except Exception as e:
        print(f"Delete expense error: {e}")
        return jsonify({'error': 'Failed to delete expense'}), 500

@app.route('/api/categories', methods=['GET'])
@login_required
def list_categories():
    try:
        categories = Category.query.all()
        category_data = []
        for c in categories:
            category_data.append({
                'id': c.id,
                'name': c.name,
                'description': c.description,
                'budget': float(c.budget) if c.budget else None
            })
        return jsonify(category_data)
    except Exception as e:
        print(f"List categories error: {e}")
        return jsonify({'error': 'Failed to load categories'}), 500

@app.route('/api/categories', methods=['POST'])
@login_required
def add_category():
    try:
        name = request.json.get('name')
        description = request.json.get('description')
        budget = request.json.get('budget')
        
        if not name:
            return jsonify({'error': 'Category name is required'}), 400
        
        if Category.query.filter_by(name=name).first():
            return jsonify({'error': 'Category already exists'}), 400
        
        new_cat = Category(
            name=name, 
            description=description, 
            budget=float(budget) if budget else None
        )
        db.session.add(new_cat)
        db.session.commit()
        return jsonify({'message': 'Category added', 'id': new_cat.id}), 201
    
    except Exception as e:
        print(f"Add category error: {e}")
        return jsonify({'error': 'Failed to add category'}), 500

@app.route('/api/categories/<int:id>', methods=['PUT'])
@login_required
def edit_category_api(id):
    try:
        category = Category.query.get_or_404(id)
        name = request.json.get('name')
        description = request.json.get('description')
        budget = request.json.get('budget')
        
        if not name:
            return jsonify({'error': 'Category name is required'}), 400
        
        if name != category.name and Category.query.filter_by(name=name).first():
            return jsonify({'error': 'Category name already exists'}), 400
        
        category.name = name
        category.description = description
        category.budget = float(budget) if budget else None
        db.session.commit()
        
        return jsonify({'message': 'Category updated'}), 200
    
    except Exception as e:
        print(f"Edit category error: {e}")
        return jsonify({'error': 'Failed to update category'}), 500

@app.route('/api/categories/<int:id>', methods=['DELETE'])
@login_required
def delete_category_api(id):
    try:
        category = Category.query.get_or_404(id)
        
        if category.expenses:
            return jsonify({'error': 'Cannot delete category with associated expenses'}), 400
        
        db.session.delete(category)
        db.session.commit()
        return jsonify({'message': 'Category deleted'}), 200
    
    except Exception as e:
        print(f"Delete category error: {e}")
        return jsonify({'error': 'Failed to delete category'}), 500

@app.route('/delete_category/<int:id>', methods=['POST'])
@login_required
@csrf.exempt
def delete_category_form(id):
    try:
        category = Category.query.get_or_404(id)
        if category.expenses:
            flash('Cannot delete category with associated expenses', 'danger')
            return redirect(url_for('add_category_page'))
        
        db.session.delete(category)
        db.session.commit()
        flash('Category deleted successfully!', 'success')
        return redirect(url_for('add_category_page'))
    
    except Exception as e:
        print(f"Delete category form error: {e}")
        flash('Failed to delete category', 'danger')
        return redirect(url_for('add_category_page'))

@app.route('/add_category', methods=['GET', 'POST'])
@login_required
@no_cache
def add_category_page():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        budget = request.form.get('budget')
        
        if not name:
            flash('Category name is required', 'danger')
        elif Category.query.filter_by(name=name).first():
            flash('Category already exists', 'danger')
        else:
            new_cat = Category(
                name=name, 
                description=description, 
                budget=float(budget) if budget else None
            )
            db.session.add(new_cat)
            db.session.commit()
            flash('Category added successfully!', 'success')
            return redirect(url_for('add_category_page'))  
    
    categories = Category.query.all()
    return render_template('add_category.html', categories=categories)

@app.route('/categories')
@login_required
@no_cache
def categories_page():
    categories = Category.query.all()
    return render_template('categories.html', categories=categories)

@app.route('/edit_category/<int:id>', methods=['GET', 'POST'])
@login_required
@no_cache
def edit_category_page(id):
    category = Category.query.get_or_404(id)
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        budget = request.form.get('budget')
        
        if not name:
            flash('Category name is required', 'danger')
            return render_template('edit_category.html', category=category)
        
        if name != category.name and Category.query.filter_by(name=name).first():
            flash('Category name already exists', 'danger')
            return render_template('edit_category.html', category=category)
        
        category.name = name
        category.description = description
        category.budget = float(budget) if budget else None
        db.session.commit()
        flash('Category updated successfully!', 'success')
        return redirect(url_for('categories_page'))
    
    return render_template('edit_category.html', category=category)

@app.route('/edit_expense/<int:id>', methods=['GET', 'POST'])
@login_required
@no_cache
def edit_expense_page(id):
    expense = Expense.query.get_or_404(id)
    if expense.user_id != current_user.id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    categories = Category.query.all()
    
    if request.method == 'POST':
        title = request.form.get('title')
        amount = request.form.get('amount')
        date = request.form.get('date')
        category_id = request.form.get('category_id')
        
        if not title or not amount or not date:
            flash('All fields are required', 'danger')
            return render_template('edit_expense.html', expense=expense, categories=categories)
        
        try:
            amount = float(amount)
            if amount <= 0:
                flash('Amount must be positive', 'danger')
                return render_template('edit_expense.html', expense=expense, categories=categories)
        except ValueError:
            flash('Invalid amount format', 'danger')
            return render_template('edit_expense.html', expense=expense, categories=categories)
        
        expense.title = title
        expense.amount = amount
        expense.date = date
        expense.category_id = int(category_id) if category_id else None
        db.session.commit()
        flash('Expense updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('edit_expense.html', expense=expense, categories=categories)

@app.route('/api/export_csv', methods=['GET'])
@login_required
def export_csv():
    try:
        expenses = Expense.query.filter_by(user_id=current_user.id).order_by(Expense.date.desc()).all()
        output = io.StringIO()
        writer = csv.writer(output)
        
        writer.writerow(['Title', 'Amount', 'Category', 'Date'])
        
        for exp in expenses:
            writer.writerow([
                exp.title, 
                exp.amount, 
                exp.category.name if exp.category else 'Uncategorized', 
                exp.date
            ])
        
        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={"Content-Disposition": "attachment;filename=expenses.csv"}
        )
    
    except Exception as e:
        print(f"Export CSV error: {e}")
        flash('Failed to export data', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/reports')
@login_required
@no_cache
def reports():
    return render_template('reports.html')

@app.route('/api/user/income', methods=['PUT'])
@login_required
def set_income():
    try:
        income = request.json.get('income')
        if income is None:
            return jsonify({'error': 'Income is required'}), 400
        
        try:
            income = float(income)
            if income < 0:
                return jsonify({'error': 'Income cannot be negative'}), 400
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid income format'}), 400
        
        current_user.income = income
        db.session.commit()
        return jsonify({'message': 'Income updated', 'income': current_user.income}), 200
    
    except Exception as e:
        print(f"Set income error: {e}")
        return jsonify({'error': 'Failed to update income'}), 500

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    try:
        logout_user()
        session.clear()
        return jsonify({'message': 'Logged out successfully'}), 200
    except Exception as e:
        print(f"Logout error: {e}")
        return jsonify({'error': 'Logout failed'}), 500

@app.context_processor
def inject_csrf_token():
    from flask_wtf.csrf import generate_csrf
    return dict(csrf_token=generate_csrf)

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(403)
def forbidden_error(error):
    return jsonify({'error': 'Forbidden'}), 403

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)