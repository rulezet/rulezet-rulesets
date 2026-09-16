rule TTP_XOR_WriteProcessMemory_152e {
  strings:
    $key_152e = { 42 5c [2] 70 7e [2] 76 4b [2] 58 4b [2] 67 57 }

  condition:
    any of them
}