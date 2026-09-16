rule TTP_XOR_WriteProcessMemory_01f0 {
  strings:
    $key_01f0 = { 56 82 [2] 64 a0 [2] 62 95 [2] 4c 95 [2] 73 89 }

  condition:
    any of them
}