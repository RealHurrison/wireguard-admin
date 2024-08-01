package db

import (
	"os"

	"wireguard-admin/model"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var DB *gorm.DB

func Init() {
	_, err := os.Stat("data")
	if os.IsNotExist(err) {
		if os.Mkdir("data", 0o600) != nil {
			panic("failed to create data directory")
		}
	}

	DB, err = gorm.Open(sqlite.Open("data/data.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	err = DB.AutoMigrate(&model.User{}, &model.Client{}, &model.Rule{})
	if err != nil {
		panic("failed to migrate database")
	}

	var count int64
	DB.Model(&model.User{}).Count(&count)
	if count == 0 {
		DB.Create(&model.User{
			UserName: "admin",
			PassWord: "admin",
		})
	}
}
