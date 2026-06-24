from database import engine, Base
import models
Base.metadata.drop_all(bind = engine)