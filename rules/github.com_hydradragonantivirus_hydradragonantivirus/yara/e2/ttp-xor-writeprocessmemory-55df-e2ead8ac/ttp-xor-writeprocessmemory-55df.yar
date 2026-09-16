rule TTP_XOR_WriteProcessMemory_55df {
  strings:
    $key_55df = { 02 ad [2] 30 8f [2] 36 ba [2] 18 ba [2] 27 a6 }

  condition:
    any of them
}