from app import app, db
from sqlalchemy import inspect

def print_schema():
    with app.app_context():
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        
        print("\n=== DATABASE SCHEMA REPORT ===")
        for table in tables:
            print(f"\n[ Table: {table} ]")
            columns = inspector.get_columns(table)
            for col in columns:
                # Prints Name, Type, and if it allows NULL
                print(f"  - {col['name']:<15} | {str(col['type']):<10} | Nullable: {col['nullable']}")
        print("\n==============================")

if __name__ == "__main__":
    print_schema()