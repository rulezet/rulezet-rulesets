rule TTP_XOR_WriteProcessMemory_c8df {
  strings:
    $key_c8df = { 9f ad [2] ad 8f [2] ab ba [2] 85 ba [2] ba a6 }

  condition:
    any of them
}