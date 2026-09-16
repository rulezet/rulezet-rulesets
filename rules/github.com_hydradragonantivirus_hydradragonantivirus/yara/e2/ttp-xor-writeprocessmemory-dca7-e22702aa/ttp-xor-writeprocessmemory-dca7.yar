rule TTP_XOR_WriteProcessMemory_dca7 {
  strings:
    $key_dca7 = { 8b d5 [2] b9 f7 [2] bf c2 [2] 91 c2 [2] ae de }

  condition:
    any of them
}