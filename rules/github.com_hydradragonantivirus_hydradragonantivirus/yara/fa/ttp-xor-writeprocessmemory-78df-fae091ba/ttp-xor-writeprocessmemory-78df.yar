rule TTP_XOR_WriteProcessMemory_78df {
  strings:
    $key_78df = { 2f ad [2] 1d 8f [2] 1b ba [2] 35 ba [2] 0a a6 }

  condition:
    any of them
}