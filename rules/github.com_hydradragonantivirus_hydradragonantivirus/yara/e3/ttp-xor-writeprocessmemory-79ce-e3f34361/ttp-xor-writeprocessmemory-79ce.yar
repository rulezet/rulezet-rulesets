rule TTP_XOR_WriteProcessMemory_79ce {
  strings:
    $key_79ce = { 2e bc [2] 1c 9e [2] 1a ab [2] 34 ab [2] 0b b7 }

  condition:
    any of them
}