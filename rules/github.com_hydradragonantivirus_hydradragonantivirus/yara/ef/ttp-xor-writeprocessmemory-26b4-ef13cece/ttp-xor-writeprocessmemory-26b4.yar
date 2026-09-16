rule TTP_XOR_WriteProcessMemory_26b4 {
  strings:
    $key_26b4 = { 71 c6 [2] 43 e4 [2] 45 d1 [2] 6b d1 [2] 54 cd }

  condition:
    any of them
}