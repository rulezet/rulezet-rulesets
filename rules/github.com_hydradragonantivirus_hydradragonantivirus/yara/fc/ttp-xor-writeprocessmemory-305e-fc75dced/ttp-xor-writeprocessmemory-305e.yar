rule TTP_XOR_WriteProcessMemory_305e {
  strings:
    $key_305e = { 67 2c [2] 55 0e [2] 53 3b [2] 7d 3b [2] 42 27 }

  condition:
    any of them
}