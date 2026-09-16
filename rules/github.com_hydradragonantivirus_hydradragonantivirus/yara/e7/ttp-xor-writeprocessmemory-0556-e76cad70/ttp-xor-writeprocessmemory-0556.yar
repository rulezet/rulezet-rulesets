rule TTP_XOR_WriteProcessMemory_0556 {
  strings:
    $key_0556 = { 52 24 [2] 60 06 [2] 66 33 [2] 48 33 [2] 77 2f }

  condition:
    any of them
}