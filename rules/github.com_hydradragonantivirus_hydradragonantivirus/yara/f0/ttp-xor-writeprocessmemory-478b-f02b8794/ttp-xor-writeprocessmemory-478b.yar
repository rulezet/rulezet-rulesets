rule TTP_XOR_WriteProcessMemory_478b {
  strings:
    $key_478b = { 10 f9 [2] 22 db [2] 24 ee [2] 0a ee [2] 35 f2 }

  condition:
    any of them
}