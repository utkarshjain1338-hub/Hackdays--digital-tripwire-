from flask import Blueprint, request, render_template
from src.core.database import get_db

store_bp = Blueprint('store', __name__)

@store_bp.route('/', methods=['GET', 'POST'])
def index():
    db = get_db()
    cursor = db.cursor()
    search_query = request.form.get('search', '')
    if search_query:
        # INTENTIONALLY VULNERABLE for honeypot demonstration
        query = f"SELECT * FROM inventory WHERE name LIKE '%{search_query}%'"
        try:
            cursor.execute(query)
            results = cursor.fetchall()
        except Exception as e:
            results = []
            print(f"Error executing query: {e}")
    else:
        cursor.execute("SELECT * FROM inventory")
        results = cursor.fetchall()
    db.close()
    return render_template('index.html', items=results, search_query=search_query)
