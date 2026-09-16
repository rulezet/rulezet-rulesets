rule TTP_XOR_WriteProcessMemory_0fc8 {
  strings:
    $key_0fc8 = { 58 ba [2] 6a 98 [2] 6c ad [2] 42 ad [2] 7d b1 }

  condition:
    any of them
}