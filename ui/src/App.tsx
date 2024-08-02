import { useState } from 'react'
import reactLogo from './assets/react.svg'
import wireguardLogo from './assets/wireguard.svg'
import './App.css'

function App() {
  const [count, setCount] = useState(0)

  return (
    <>
      <div>
        <a href="https://www.wireguard.com" target="_blank">
          <img src={wireguardLogo} className="logo" alt="Wireguard logo" />
        </a>
        <a href="https://react.dev" target="_blank">
          <img src={reactLogo} className="logo react" alt="React logo" />
        </a>
      </div>
      <h1>Wireguard + React</h1>
      <div className="card">
        <button onClick={() => setCount((count) => count + 1)}>
          count is {count}
        </button>
        <p>
          Edit <code>src/App.tsx</code> and save to test HMR
        </p>
      </div>
      <p className="read-the-docs">
        Click on the Wireguard and React logos to learn more
      </p>
    </>
  )
}

export default App
