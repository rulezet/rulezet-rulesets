rule TTP_XOR_WriteProcessMemory_6cb1 {
  strings:
    $key_6cb1 = { 3b c3 [2] 09 e1 [2] 0f d4 [2] 21 d4 [2] 1e c8 }

  condition:
    any of them
}