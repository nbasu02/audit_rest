from flask_script import Manager
from app import app, db
from flask_migrate import Migrate, MigrateCommand

manager = Manager(app)
app.debug = True
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)

if __name__ == "__main__":
    manager.run()
