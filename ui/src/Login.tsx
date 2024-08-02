import { App, Button, Flex } from "antd"
import { Input } from "antd";


const Login = () => {
    const { notification } = App.useApp()

    return (
        <Flex justify="center" align="center" style={{ height: '100vh', width: '100vw' }}>
            <Flex vertical justify="center" align="center">
                <h1>Login</h1>
                <Input placeholder="Username"/>
                <Input placeholder="Password"/>
                <Button type="primary">Login</Button>
            </Flex>

        </Flex>
    )
}

export { Login }