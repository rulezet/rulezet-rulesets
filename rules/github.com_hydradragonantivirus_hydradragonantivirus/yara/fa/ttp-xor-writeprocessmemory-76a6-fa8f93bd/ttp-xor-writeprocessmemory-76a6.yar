rule TTP_XOR_WriteProcessMemory_76a6 {
  strings:
    $key_76a6 = { 21 d4 [2] 13 f6 [2] 15 c3 [2] 3b c3 [2] 04 df }

  condition:
    any of them
}