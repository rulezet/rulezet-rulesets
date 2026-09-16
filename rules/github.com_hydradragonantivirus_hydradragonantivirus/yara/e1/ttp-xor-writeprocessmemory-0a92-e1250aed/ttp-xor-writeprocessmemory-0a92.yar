rule TTP_XOR_WriteProcessMemory_0a92 {
  strings:
    $key_0a92 = { 5d e0 [2] 6f c2 [2] 69 f7 [2] 47 f7 [2] 78 eb }

  condition:
    any of them
}