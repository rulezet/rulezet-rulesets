rule TTP_XOR_WriteProcessMemory_da4b {
  strings:
    $key_da4b = { 8d 39 [2] bf 1b [2] b9 2e [2] 97 2e [2] a8 32 }

  condition:
    any of them
}