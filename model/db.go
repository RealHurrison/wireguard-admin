package model

import "time"

type Audit struct {
	CreatedAt time.Time
	UpdatedAt time.Time
}

type User struct {
	Audit

	ID       string `gorm:"type:uuid;primary_key"`
	UserName string `gorm:"unique;not null;default:null"`
	PassWord string `gorm:"not null;default:null"`
}

type Client struct {
	Audit

	ID           string `gorm:"type:uuid;primary_key" json:"id"`
	Name         string `gorm:"unique;not null;default:null" json:"name"`
	PrivateKey   string `gorm:"unique;not null;default:null" json:"private_key"`
	PublicKey    string `gorm:"unique;not null;default:null" json:"public_key"`
	PresharedKey string `gorm:"unique;not null;default:null" json:"preshared_key"`
	IP           string `gorm:"unique;not null;default:null" json:"ip"`
	DNS          string `json:"dns"`
	Route        string `json:"route"`
	Rules        []Rule `gorm:"foreignKey:ClientID" json:"-"`
}

type Rule struct {
	Audit

	ID       string `gorm:"type:uuid;primary_key" json:"id"`
	ClientID string `gorm:"type:uuid;not null;index:idx_unique,unique" json:"-"`
	Protocol string `json:"protocol"`
	DestIP   string `json:"dest_ip"`
	DestPort string `json:"dest_port"`
	Action   string `json:"action"`
	Priority int    `gorm:"not null;index:idx_unique,unique" json:"priority"`
}
