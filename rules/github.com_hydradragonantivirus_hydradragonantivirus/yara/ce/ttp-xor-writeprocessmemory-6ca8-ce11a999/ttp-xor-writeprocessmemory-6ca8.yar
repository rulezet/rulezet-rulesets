rule TTP_XOR_WriteProcessMemory_6ca8 {
  strings:
    $key_6ca8 = { 3b da [2] 09 f8 [2] 0f cd [2] 21 cd [2] 1e d1 }

  condition:
    any of them
}