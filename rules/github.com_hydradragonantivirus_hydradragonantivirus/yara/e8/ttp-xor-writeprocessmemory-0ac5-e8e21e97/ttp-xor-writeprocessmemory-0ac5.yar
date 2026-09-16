rule TTP_XOR_WriteProcessMemory_0ac5 {
  strings:
    $key_0ac5 = { 5d b7 [2] 6f 95 [2] 69 a0 [2] 47 a0 [2] 78 bc }

  condition:
    any of them
}