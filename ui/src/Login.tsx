import { App, Button, Flex, InputRef, Space } from "antd"
import { Input } from "antd";
import React from "react";
import wireguardLogo from './assets/wireguard.svg'
import style from './Login.module.scss'
import Api from './api'

const Login = () => {
    const { notification } = App.useApp()
    const usernameRef = React.useRef<InputRef>(null);
    const passwordRef = React.useRef<InputRef>(null);
    const api = new Api(null)

    return (
        <Flex justify="center" align="center" style={{ height: '100vh', width: '100vw' }}>
            <Flex vertical justify="center" align="center">
                <img src={wireguardLogo} alt="Wireguard Logo" className={style.logo} />
                <span className={style.title}>Wireguard Admin Panel</span>
                <Space direction="vertical" align="center" size="small">
                    <Input ref={usernameRef} placeholder="Username" className={style.input} />
                    <Input.Password ref={passwordRef} placeholder="Password" className={style.input} />
                    <Button type="primary" onClick={ async () => {
                        const username = usernameRef.current!.input!.value
                        const password = passwordRef.current!.input!.value
                        
                        try {
                            await api.login(username, password)
                            notification.success({ message: 'Login Successful'})
                        } catch (error) {
                            notification.error({ message: error as string })
                        }
                    }}>Login</Button>
                </Space>
            </Flex>

        </Flex>
    )
}

export { Login }