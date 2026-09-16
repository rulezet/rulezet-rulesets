rule TTP_XOR_WriteProcessMemory_09b1 {
  strings:
    $key_09b1 = { 5e c3 [2] 6c e1 [2] 6a d4 [2] 44 d4 [2] 7b c8 }

  condition:
    any of them
}