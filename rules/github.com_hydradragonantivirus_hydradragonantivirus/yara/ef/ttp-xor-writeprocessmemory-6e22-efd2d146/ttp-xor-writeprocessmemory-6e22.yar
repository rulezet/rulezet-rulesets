rule TTP_XOR_WriteProcessMemory_6e22 {
  strings:
    $key_6e22 = { 39 50 [2] 0b 72 [2] 0d 47 [2] 23 47 [2] 1c 5b }

  condition:
    any of them
}