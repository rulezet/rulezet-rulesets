rule TTP_XOR_WriteProcessMemory_7410 {
  strings:
    $key_7410 = { 23 62 [2] 11 40 [2] 17 75 [2] 39 75 [2] 06 69 }

  condition:
    any of them
}