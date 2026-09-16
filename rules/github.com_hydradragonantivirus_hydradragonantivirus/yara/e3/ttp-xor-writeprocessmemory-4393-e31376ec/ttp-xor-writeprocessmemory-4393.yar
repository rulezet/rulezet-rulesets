rule TTP_XOR_WriteProcessMemory_4393 {
  strings:
    $key_4393 = { 14 e1 [2] 26 c3 [2] 20 f6 [2] 0e f6 [2] 31 ea }

  condition:
    any of them
}