rule TTP_XOR_WriteProcessMemory_fcb9 {
  strings:
    $key_fcb9 = { ab cb [2] 99 e9 [2] 9f dc [2] b1 dc [2] 8e c0 }

  condition:
    any of them
}