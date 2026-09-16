rule TTP_XOR_WriteProcessMemory_3ca7 {
  strings:
    $key_3ca7 = { 6b d5 [2] 59 f7 [2] 5f c2 [2] 71 c2 [2] 4e de }

  condition:
    any of them
}