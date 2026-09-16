rule TTP_XOR_WriteProcessMemory_e3b4 {
  strings:
    $key_e3b4 = { b4 c6 [2] 86 e4 [2] 80 d1 [2] ae d1 [2] 91 cd }

  condition:
    any of them
}