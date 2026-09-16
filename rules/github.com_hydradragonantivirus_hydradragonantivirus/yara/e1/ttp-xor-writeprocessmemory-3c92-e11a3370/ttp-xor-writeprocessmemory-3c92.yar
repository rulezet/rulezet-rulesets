rule TTP_XOR_WriteProcessMemory_3c92 {
  strings:
    $key_3c92 = { 6b e0 [2] 59 c2 [2] 5f f7 [2] 71 f7 [2] 4e eb }

  condition:
    any of them
}