rule TTP_XOR_WriteProcessMemory_6dfb {
  strings:
    $key_6dfb = { 3a 89 [2] 08 ab [2] 0e 9e [2] 20 9e [2] 1f 82 }

  condition:
    any of them
}