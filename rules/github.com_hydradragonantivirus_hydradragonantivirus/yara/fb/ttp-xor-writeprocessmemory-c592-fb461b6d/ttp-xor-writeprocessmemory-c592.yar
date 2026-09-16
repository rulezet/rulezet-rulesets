rule TTP_XOR_WriteProcessMemory_c592 {
  strings:
    $key_c592 = { 92 e0 [2] a0 c2 [2] a6 f7 [2] 88 f7 [2] b7 eb }

  condition:
    any of them
}