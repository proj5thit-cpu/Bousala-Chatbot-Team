# run.py
import os
from app import create_app

# Create the Flask app using the factory function
app = create_app()

# -----------------------------
# Ensure app context is pushed
# -----------------------------
with app.app_context():
    from app.routes import init_decision_tree
    init_decision_tree(app)

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    # Run the app
    app.run(host='0.0.0.0', port=port, debug=True)
