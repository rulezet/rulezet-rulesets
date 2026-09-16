rule TTP_XOR_WriteProcessMemory_408b {
  strings:
    $key_408b = { 17 f9 [2] 25 db [2] 23 ee [2] 0d ee [2] 32 f2 }

  condition:
    any of them
}