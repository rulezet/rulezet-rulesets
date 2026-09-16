rule TTP_XOR_WriteProcessMemory_2ba0 {
  strings:
    $key_2ba0 = { 7c d2 [2] 4e f0 [2] 48 c5 [2] 66 c5 [2] 59 d9 }

  condition:
    any of them
}