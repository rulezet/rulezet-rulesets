rule TTP_XOR_WriteProcessMemory_3b5b {
  strings:
    $key_3b5b = { 6c 29 [2] 5e 0b [2] 58 3e [2] 76 3e [2] 49 22 }

  condition:
    any of them
}