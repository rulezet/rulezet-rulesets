rule TTP_XOR_WriteProcessMemory_2ca6 {
  strings:
    $key_2ca6 = { 7b d4 [2] 49 f6 [2] 4f c3 [2] 61 c3 [2] 5e df }

  condition:
    any of them
}