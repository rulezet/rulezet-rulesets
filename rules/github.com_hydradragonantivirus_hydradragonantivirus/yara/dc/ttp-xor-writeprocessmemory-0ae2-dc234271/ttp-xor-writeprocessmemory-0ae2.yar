rule TTP_XOR_WriteProcessMemory_0ae2 {
  strings:
    $key_0ae2 = { 5d 90 [2] 6f b2 [2] 69 87 [2] 47 87 [2] 78 9b }

  condition:
    any of them
}