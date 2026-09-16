rule TTP_XOR_WriteProcessMemory_4ea0 {
  strings:
    $key_4ea0 = { 19 d2 [2] 2b f0 [2] 2d c5 [2] 03 c5 [2] 3c d9 }

  condition:
    any of them
}