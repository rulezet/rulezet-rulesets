rule TTP_XOR_WriteProcessMemory_1496 {
  strings:
    $key_1496 = { 43 e4 [2] 71 c6 [2] 77 f3 [2] 59 f3 [2] 66 ef }

  condition:
    any of them
}