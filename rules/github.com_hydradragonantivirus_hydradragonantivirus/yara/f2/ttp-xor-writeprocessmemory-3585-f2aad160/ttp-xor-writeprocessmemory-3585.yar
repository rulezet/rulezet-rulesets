rule TTP_XOR_WriteProcessMemory_3585 {
  strings:
    $key_3585 = { 62 f7 [2] 50 d5 [2] 56 e0 [2] 78 e0 [2] 47 fc }

  condition:
    any of them
}