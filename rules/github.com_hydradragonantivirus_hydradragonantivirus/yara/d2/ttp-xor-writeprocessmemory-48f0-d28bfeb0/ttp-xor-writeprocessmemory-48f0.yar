rule TTP_XOR_WriteProcessMemory_48f0 {
  strings:
    $key_48f0 = { 1f 82 [2] 2d a0 [2] 2b 95 [2] 05 95 [2] 3a 89 }

  condition:
    any of them
}