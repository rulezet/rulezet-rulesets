rule TTP_XOR_WriteProcessMemory_dca6 {
  strings:
    $key_dca6 = { 8b d4 [2] b9 f6 [2] bf c3 [2] 91 c3 [2] ae df }

  condition:
    any of them
}