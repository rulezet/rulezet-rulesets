rule TTP_XOR_WriteProcessMemory_1787 {
  strings:
    $key_1787 = { 40 f5 [2] 72 d7 [2] 74 e2 [2] 5a e2 [2] 65 fe }

  condition:
    any of them
}