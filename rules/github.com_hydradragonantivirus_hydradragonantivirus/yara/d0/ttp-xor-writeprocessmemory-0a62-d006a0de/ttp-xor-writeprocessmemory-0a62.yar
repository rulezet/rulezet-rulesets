rule TTP_XOR_WriteProcessMemory_0a62 {
  strings:
    $key_0a62 = { 5d 10 [2] 6f 32 [2] 69 07 [2] 47 07 [2] 78 1b }

  condition:
    any of them
}