rule TTP_XOR_WriteProcessMemory_e384 {
  strings:
    $key_e384 = { b4 f6 [2] 86 d4 [2] 80 e1 [2] ae e1 [2] 91 fd }

  condition:
    any of them
}