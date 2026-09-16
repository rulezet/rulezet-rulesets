rule TTP_XOR_WriteProcessMemory_76a0 {
  strings:
    $key_76a0 = { 21 d2 [2] 13 f0 [2] 15 c5 [2] 3b c5 [2] 04 d9 }

  condition:
    any of them
}