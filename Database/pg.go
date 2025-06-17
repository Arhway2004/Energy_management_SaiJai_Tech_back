package Database

import (
    "gorm.io/driver/postgres"
    "gorm.io/gorm"
)


func InitDB() (*gorm.DB, error) {
    dsn := "host=DB_HOST user=DB_USER password=DB_PASSWORD dbname=DB_NAME port=DB_PORT sslmode=disable TimeZone=UTC"
    db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
    if err != nil {
        return nil, err
    }
    return db, nil
}
