rule TTP_XOR_WriteProcessMemory_7f91 {
  strings:
    $key_7f91 = { 28 e3 [2] 1a c1 [2] 1c f4 [2] 32 f4 [2] 0d e8 }

  condition:
    any of them
}