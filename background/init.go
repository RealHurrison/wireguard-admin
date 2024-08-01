package background

func Init() {
	go gracefulExit()
}
