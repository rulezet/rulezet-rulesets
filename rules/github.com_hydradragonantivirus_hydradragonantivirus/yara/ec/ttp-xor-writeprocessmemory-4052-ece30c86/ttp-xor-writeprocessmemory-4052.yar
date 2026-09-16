rule TTP_XOR_WriteProcessMemory_4052 {
  strings:
    $key_4052 = { 17 20 [2] 25 02 [2] 23 37 [2] 0d 37 [2] 32 2b }

  condition:
    any of them
}