rule TTP_XOR_WriteProcessMemory_7682 {
  strings:
    $key_7682 = { 21 f0 [2] 13 d2 [2] 15 e7 [2] 3b e7 [2] 04 fb }

  condition:
    any of them
}