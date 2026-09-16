rule TTP_XOR_WriteProcessMemory_6e32 {
  strings:
    $key_6e32 = { 39 40 [2] 0b 62 [2] 0d 57 [2] 23 57 [2] 1c 4b }

  condition:
    any of them
}