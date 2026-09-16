rule TTP_XOR_WriteProcessMemory_51df {
  strings:
    $key_51df = { 06 ad [2] 34 8f [2] 32 ba [2] 1c ba [2] 23 a6 }

  condition:
    any of them
}