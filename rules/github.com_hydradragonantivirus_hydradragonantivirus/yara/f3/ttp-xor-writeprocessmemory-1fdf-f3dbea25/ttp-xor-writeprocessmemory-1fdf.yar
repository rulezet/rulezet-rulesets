rule TTP_XOR_WriteProcessMemory_1fdf {
  strings:
    $key_1fdf = { 48 ad [2] 7a 8f [2] 7c ba [2] 52 ba [2] 6d a6 }

  condition:
    any of them
}