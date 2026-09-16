rule TTP_XOR_WriteProcessMemory_3c21 {
  strings:
    $key_3c21 = { 6b 53 [2] 59 71 [2] 5f 44 [2] 71 44 [2] 4e 58 }

  condition:
    any of them
}