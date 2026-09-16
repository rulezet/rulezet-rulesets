rule TTP_XOR_WriteProcessMemory_61df {
  strings:
    $key_61df = { 36 ad [2] 04 8f [2] 02 ba [2] 2c ba [2] 13 a6 }

  condition:
    any of them
}