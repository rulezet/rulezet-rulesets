rule TTP_XOR_WriteProcessMemory_dcb5 {
  strings:
    $key_dcb5 = { 8b c7 [2] b9 e5 [2] bf d0 [2] 91 d0 [2] ae cc }

  condition:
    any of them
}