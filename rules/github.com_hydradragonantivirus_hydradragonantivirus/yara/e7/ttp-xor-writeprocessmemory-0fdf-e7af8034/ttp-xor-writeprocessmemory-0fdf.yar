rule TTP_XOR_WriteProcessMemory_0fdf {
  strings:
    $key_0fdf = { 58 ad [2] 6a 8f [2] 6c ba [2] 42 ba [2] 7d a6 }

  condition:
    any of them
}