rule TTP_XOR_WriteProcessMemory_da5b {
  strings:
    $key_da5b = { 8d 29 [2] bf 0b [2] b9 3e [2] 97 3e [2] a8 22 }

  condition:
    any of them
}