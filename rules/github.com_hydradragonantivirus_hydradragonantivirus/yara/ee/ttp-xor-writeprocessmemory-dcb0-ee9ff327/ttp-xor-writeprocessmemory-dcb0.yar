rule TTP_XOR_WriteProcessMemory_dcb0 {
  strings:
    $key_dcb0 = { 8b c2 [2] b9 e0 [2] bf d5 [2] 91 d5 [2] ae c9 }

  condition:
    any of them
}