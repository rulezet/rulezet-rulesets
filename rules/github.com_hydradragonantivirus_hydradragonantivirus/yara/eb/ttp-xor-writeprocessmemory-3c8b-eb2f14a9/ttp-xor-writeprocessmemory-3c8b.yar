rule TTP_XOR_WriteProcessMemory_3c8b {
  strings:
    $key_3c8b = { 6b f9 [2] 59 db [2] 5f ee [2] 71 ee [2] 4e f2 }

  condition:
    any of them
}