rule TTP_XOR_WriteProcessMemory_73df {
  strings:
    $key_73df = { 24 ad [2] 16 8f [2] 10 ba [2] 3e ba [2] 01 a6 }

  condition:
    any of them
}