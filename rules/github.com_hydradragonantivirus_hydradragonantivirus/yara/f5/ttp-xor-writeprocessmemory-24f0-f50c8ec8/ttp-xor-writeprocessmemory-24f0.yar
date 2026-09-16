rule TTP_XOR_WriteProcessMemory_24f0 {
  strings:
    $key_24f0 = { 73 82 [2] 41 a0 [2] 47 95 [2] 69 95 [2] 56 89 }

  condition:
    any of them
}