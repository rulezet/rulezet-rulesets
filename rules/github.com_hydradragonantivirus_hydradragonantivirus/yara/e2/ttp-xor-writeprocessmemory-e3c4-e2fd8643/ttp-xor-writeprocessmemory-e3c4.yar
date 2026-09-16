rule TTP_XOR_WriteProcessMemory_e3c4 {
  strings:
    $key_e3c4 = { b4 b6 [2] 86 94 [2] 80 a1 [2] ae a1 [2] 91 bd }

  condition:
    any of them
}