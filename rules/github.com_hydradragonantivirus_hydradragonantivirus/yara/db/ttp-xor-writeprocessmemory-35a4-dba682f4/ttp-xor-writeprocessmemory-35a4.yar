rule TTP_XOR_WriteProcessMemory_35a4 {
  strings:
    $key_35a4 = { 62 d6 [2] 50 f4 [2] 56 c1 [2] 78 c1 [2] 47 dd }

  condition:
    any of them
}