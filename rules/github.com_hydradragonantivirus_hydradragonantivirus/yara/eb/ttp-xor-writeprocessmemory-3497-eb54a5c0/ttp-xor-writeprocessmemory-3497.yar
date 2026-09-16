rule TTP_XOR_WriteProcessMemory_3497 {
  strings:
    $key_3497 = { 63 e5 [2] 51 c7 [2] 57 f2 [2] 79 f2 [2] 46 ee }

  condition:
    any of them
}