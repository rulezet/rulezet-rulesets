rule TTP_XOR_WriteProcessMemory_0526 {
  strings:
    $key_0526 = { 52 54 [2] 60 76 [2] 66 43 [2] 48 43 [2] 77 5f }

  condition:
    any of them
}