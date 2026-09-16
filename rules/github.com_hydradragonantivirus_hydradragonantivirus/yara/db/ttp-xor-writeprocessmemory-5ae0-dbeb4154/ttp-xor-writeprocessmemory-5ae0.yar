rule TTP_XOR_WriteProcessMemory_5ae0 {
  strings:
    $key_5ae0 = { 0d 92 [2] 3f b0 [2] 39 85 [2] 17 85 [2] 28 99 }

  condition:
    any of them
}