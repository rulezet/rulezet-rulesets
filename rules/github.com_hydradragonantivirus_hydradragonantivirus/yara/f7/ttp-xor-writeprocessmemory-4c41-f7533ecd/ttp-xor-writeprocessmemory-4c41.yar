rule TTP_XOR_WriteProcessMemory_4c41 {
  strings:
    $key_4c41 = { 1b 33 [2] 29 11 [2] 2f 24 [2] 01 24 [2] 3e 38 }

  condition:
    any of them
}