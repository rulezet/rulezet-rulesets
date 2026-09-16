rule TTP_XOR_WriteProcessMemory_6da3 {
  strings:
    $key_6da3 = { 3a d1 [2] 08 f3 [2] 0e c6 [2] 20 c6 [2] 1f da }

  condition:
    any of them
}