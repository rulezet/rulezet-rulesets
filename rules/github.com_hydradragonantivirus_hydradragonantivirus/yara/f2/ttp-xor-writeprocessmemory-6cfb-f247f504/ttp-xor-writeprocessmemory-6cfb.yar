rule TTP_XOR_WriteProcessMemory_6cfb {
  strings:
    $key_6cfb = { 3b 89 [2] 09 ab [2] 0f 9e [2] 21 9e [2] 1e 82 }

  condition:
    any of them
}