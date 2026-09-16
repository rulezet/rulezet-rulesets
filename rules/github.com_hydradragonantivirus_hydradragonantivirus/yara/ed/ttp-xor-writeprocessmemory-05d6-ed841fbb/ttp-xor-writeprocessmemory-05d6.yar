rule TTP_XOR_WriteProcessMemory_05d6 {
  strings:
    $key_05d6 = { 52 a4 [2] 60 86 [2] 66 b3 [2] 48 b3 [2] 77 af }

  condition:
    any of them
}