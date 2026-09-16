rule TTP_XOR_WriteProcessMemory_dcf6 {
  strings:
    $key_dcf6 = { 8b 84 [2] b9 a6 [2] bf 93 [2] 91 93 [2] ae 8f }

  condition:
    any of them
}