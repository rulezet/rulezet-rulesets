rule TTP_XOR_WriteProcessMemory_4c42 {
  strings:
    $key_4c42 = { 1b 30 [2] 29 12 [2] 2f 27 [2] 01 27 [2] 3e 3b }

  condition:
    any of them
}