rule TTP_XOR_WriteProcessMemory_da93 {
  strings:
    $key_da93 = { 8d e1 [2] bf c3 [2] b9 f6 [2] 97 f6 [2] a8 ea }

  condition:
    any of them
}