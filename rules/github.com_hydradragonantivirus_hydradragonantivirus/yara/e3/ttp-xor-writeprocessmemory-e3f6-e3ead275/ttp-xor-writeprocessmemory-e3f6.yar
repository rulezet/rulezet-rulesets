rule TTP_XOR_WriteProcessMemory_e3f6 {
  strings:
    $key_e3f6 = { b4 84 [2] 86 a6 [2] 80 93 [2] ae 93 [2] 91 8f }

  condition:
    any of them
}