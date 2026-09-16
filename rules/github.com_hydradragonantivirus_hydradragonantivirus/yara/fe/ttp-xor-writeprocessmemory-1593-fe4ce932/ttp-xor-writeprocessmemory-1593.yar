rule TTP_XOR_WriteProcessMemory_1593 {
  strings:
    $key_1593 = { 42 e1 [2] 70 c3 [2] 76 f6 [2] 58 f6 [2] 67 ea }

  condition:
    any of them
}