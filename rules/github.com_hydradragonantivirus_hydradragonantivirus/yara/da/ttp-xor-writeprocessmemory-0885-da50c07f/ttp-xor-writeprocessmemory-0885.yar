rule TTP_XOR_WriteProcessMemory_0885 {
  strings:
    $key_0885 = { 5f f7 [2] 6d d5 [2] 6b e0 [2] 45 e0 [2] 7a fc }

  condition:
    any of them
}