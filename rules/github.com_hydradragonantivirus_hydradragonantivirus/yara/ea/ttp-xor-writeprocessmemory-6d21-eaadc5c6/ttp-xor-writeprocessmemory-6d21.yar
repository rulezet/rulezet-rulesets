rule TTP_XOR_WriteProcessMemory_6d21 {
  strings:
    $key_6d21 = { 3a 53 [2] 08 71 [2] 0e 44 [2] 20 44 [2] 1f 58 }

  condition:
    any of them
}