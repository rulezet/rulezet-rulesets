rule TTP_XOR_WriteProcessMemory_08a5 {
  strings:
    $key_08a5 = { 5f d7 [2] 6d f5 [2] 6b c0 [2] 45 c0 [2] 7a dc }

  condition:
    any of them
}