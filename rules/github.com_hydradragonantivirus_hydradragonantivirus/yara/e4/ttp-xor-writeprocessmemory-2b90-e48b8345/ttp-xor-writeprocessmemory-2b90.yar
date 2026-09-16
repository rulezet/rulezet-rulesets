rule TTP_XOR_WriteProcessMemory_2b90 {
  strings:
    $key_2b90 = { 7c e2 [2] 4e c0 [2] 48 f5 [2] 66 f5 [2] 59 e9 }

  condition:
    any of them
}