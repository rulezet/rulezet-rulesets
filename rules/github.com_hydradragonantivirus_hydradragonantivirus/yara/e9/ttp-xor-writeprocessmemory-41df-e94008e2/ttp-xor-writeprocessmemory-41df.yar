rule TTP_XOR_WriteProcessMemory_41df {
  strings:
    $key_41df = { 16 ad [2] 24 8f [2] 22 ba [2] 0c ba [2] 33 a6 }

  condition:
    any of them
}