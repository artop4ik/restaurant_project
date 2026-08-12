from sqlalchemy import Column, create_engine, String, Boolean, DateTime, ForeignKey, JSON, Integer
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import JSONB
from flask_login import UserMixin
import bcrypt
from datetime import datetime




# База даних SQLite
DATABASE_FILE = "online_restaurant.db"
engine = create_engine(f"sqlite:///{DATABASE_FILE}", echo=True)
Session = sessionmaker(bind=engine)


# Фіксований список категорій страв
CATEGORIES = [
    "Піца",
    "Паста",
    "Салати",
    "Супи",
    "Закуски",
    "М'ясні страви",
    "Напої",
    "Десерти",
]

# Фіксований список типів столиків для бронювання
TABLE_TYPES = [
    "2-місний",
    "4-місний",
    "6-місний",
    "VIP-зона",
]

# Статуси бронювання
RESERVATION_STATUSES = ["pending", "confirmed", "cancelled"]


class Base(DeclarativeBase):
    pass


class Users(Base, UserMixin):
    __tablename__ = "users"
  
    id: Mapped[int] = mapped_column(primary_key=True)
    nickname: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(200))
    email: Mapped[str] = mapped_column(String(50), unique=True)
    role = Column(String(20), nullable=False, default="user")

    reservations = relationship("Reservation", foreign_keys="Reservation.user_id", back_populates="user")
    orders = relationship("Orders", foreign_keys="Orders.user_id", back_populates='user')

    def set_password(self, password: str):
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password: str):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))


class Menu(Base):
    __tablename__ = "menu"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String)
    weight: Mapped[str] = mapped_column(String)
    ingredients: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(String)
    price: Mapped[int] = mapped_column()
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    file_name: Mapped[str] = mapped_column(String)
    category: Mapped[str] = mapped_column(String(50), default="Інше")


class Reservation(Base):
    __tablename__ = "reservation"
    id: Mapped[int] = mapped_column(primary_key=True)
    time_start: Mapped[datetime] = mapped_column(DateTime)
    type_table: Mapped[str] = mapped_column(String(20))
    guests: Mapped[int] = mapped_column(Integer, default=2)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'))

    user = relationship("Users", foreign_keys="Reservation.user_id", back_populates="reservations")


class Orders(Base):
    __tablename__ = "orders"
    id: Mapped[int] = mapped_column(primary_key=True)
    order_list: Mapped[dict] = mapped_column(JSON)
    order_time: Mapped[datetime] = mapped_column(DateTime)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    status: Mapped[str] = mapped_column(String(20), default='pending')
    user = relationship("Users", foreign_keys="Orders.user_id", back_populates="orders")
    total_price: Mapped[float] = mapped_column()

if __name__ == '__main__':
    Base.metadata.create_all(engine)