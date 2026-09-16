rule TTP_XOR_WriteProcessMemory_e8df {
  strings:
    $key_e8df = { bf ad [2] 8d 8f [2] 8b ba [2] a5 ba [2] 9a a6 }

  condition:
    any of them
}