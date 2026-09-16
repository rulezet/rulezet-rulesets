rule TTP_XOR_WriteProcessMemory_42df {
  strings:
    $key_42df = { 15 ad [2] 27 8f [2] 21 ba [2] 0f ba [2] 30 a6 }

  condition:
    any of them
}