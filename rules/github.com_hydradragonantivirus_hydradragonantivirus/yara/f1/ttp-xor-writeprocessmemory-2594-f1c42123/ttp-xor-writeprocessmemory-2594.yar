rule TTP_XOR_WriteProcessMemory_2594 {
  strings:
    $key_2594 = { 72 e6 [2] 40 c4 [2] 46 f1 [2] 68 f1 [2] 57 ed }

  condition:
    any of them
}