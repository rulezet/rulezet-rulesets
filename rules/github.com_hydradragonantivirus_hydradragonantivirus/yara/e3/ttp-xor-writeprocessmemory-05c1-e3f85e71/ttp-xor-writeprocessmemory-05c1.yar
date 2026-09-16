rule TTP_XOR_WriteProcessMemory_05c1 {
  strings:
    $key_05c1 = { 52 b3 [2] 60 91 [2] 66 a4 [2] 48 a4 [2] 77 b8 }

  condition:
    any of them
}