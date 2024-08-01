package config

import "github.com/BurntSushi/toml"

var CONFIG *Config

func Init() {
	CONFIG = &Config{}

	_, err := toml.DecodeFile("config.toml", CONFIG)
	if err != nil {
		panic("failed to load config: " + err.Error())
	}
}
