rule TTP_XOR_WriteProcessMemory_1ca7 {
  strings:
    $key_1ca7 = { 4b d5 [2] 79 f7 [2] 7f c2 [2] 51 c2 [2] 6e de }

  condition:
    any of them
}