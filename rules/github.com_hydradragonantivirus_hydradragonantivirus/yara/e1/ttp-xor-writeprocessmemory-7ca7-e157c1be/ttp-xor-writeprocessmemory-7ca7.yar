rule TTP_XOR_WriteProcessMemory_7ca7 {
  strings:
    $key_7ca7 = { 2b d5 [2] 19 f7 [2] 1f c2 [2] 31 c2 [2] 0e de }

  condition:
    any of them
}