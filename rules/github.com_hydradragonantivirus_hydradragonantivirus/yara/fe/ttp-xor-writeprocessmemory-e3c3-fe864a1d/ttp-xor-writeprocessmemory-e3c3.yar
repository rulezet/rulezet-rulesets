rule TTP_XOR_WriteProcessMemory_e3c3 {
  strings:
    $key_e3c3 = { b4 b1 [2] 86 93 [2] 80 a6 [2] ae a6 [2] 91 ba }

  condition:
    any of them
}