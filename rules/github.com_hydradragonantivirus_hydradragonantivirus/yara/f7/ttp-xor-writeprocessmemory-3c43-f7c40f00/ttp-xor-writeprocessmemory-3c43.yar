rule TTP_XOR_WriteProcessMemory_3c43 {
  strings:
    $key_3c43 = { 6b 31 [2] 59 13 [2] 5f 26 [2] 71 26 [2] 4e 3a }

  condition:
    any of them
}