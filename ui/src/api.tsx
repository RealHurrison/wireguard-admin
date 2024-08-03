import axios, { AxiosInstance } from 'axios'

class Api {

    private client: AxiosInstance

    constructor(token: string | null) {
        this.client = axios.create({
            baseURL: '/api',
            headers: {
                Authorization: token ? `Bearer ${token}` : ''
            },
            timeout: 5000,
            withCredentials: false,
        })
    }

    async login(username: string, password: string) {
        return new Promise<string>((resolve, reject) => {
            this.client.post('/login', { username, password }).then((response) => {
                resolve(response.data.data.token)
            }).catch((error) => {
                if (error.response.status !== 404) {
                    reject('Invalid username or password')
                    return
                } else {
                    console.error(error)
                    reject('An unknown error occurred')
                    return
                }
            })
        })
    }
}

export default Api