rule TTP_XOR_WriteProcessMemory_3f80 {
  strings:
    $key_3f80 = { 68 f2 [2] 5a d0 [2] 5c e5 [2] 72 e5 [2] 4d f9 }

  condition:
    any of them
}