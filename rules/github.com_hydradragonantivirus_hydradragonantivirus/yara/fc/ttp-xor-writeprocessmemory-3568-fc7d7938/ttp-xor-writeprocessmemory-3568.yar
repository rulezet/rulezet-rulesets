rule TTP_XOR_WriteProcessMemory_3568 {
  strings:
    $key_3568 = { 62 1a [2] 50 38 [2] 56 0d [2] 78 0d [2] 47 11 }

  condition:
    any of them
}