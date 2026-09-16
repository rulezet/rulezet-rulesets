rule TTP_XOR_WriteProcessMemory_08a3 {
  strings:
    $key_08a3 = { 5f d1 [2] 6d f3 [2] 6b c6 [2] 45 c6 [2] 7a da }

  condition:
    any of them
}