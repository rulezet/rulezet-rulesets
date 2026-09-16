rule TTP_XOR_WriteProcessMemory_0596 {
  strings:
    $key_0596 = { 52 e4 [2] 60 c6 [2] 66 f3 [2] 48 f3 [2] 77 ef }

  condition:
    any of them
}