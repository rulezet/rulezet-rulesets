rule TTP_XOR_WriteProcessMemory_7ae0 {
  strings:
    $key_7ae0 = { 2d 92 [2] 1f b0 [2] 19 85 [2] 37 85 [2] 08 99 }

  condition:
    any of them
}