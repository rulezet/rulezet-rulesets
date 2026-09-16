rule TTP_XOR_WriteProcessMemory_dc56 {
  strings:
    $key_dc56 = { 8b 24 [2] b9 06 [2] bf 33 [2] 91 33 [2] ae 2f }

  condition:
    any of them
}