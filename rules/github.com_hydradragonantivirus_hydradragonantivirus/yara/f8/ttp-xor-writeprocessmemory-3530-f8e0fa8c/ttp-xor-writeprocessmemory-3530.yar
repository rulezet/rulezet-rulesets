rule TTP_XOR_WriteProcessMemory_3530 {
  strings:
    $key_3530 = { 62 42 [2] 50 60 [2] 56 55 [2] 78 55 [2] 47 49 }

  condition:
    any of them
}