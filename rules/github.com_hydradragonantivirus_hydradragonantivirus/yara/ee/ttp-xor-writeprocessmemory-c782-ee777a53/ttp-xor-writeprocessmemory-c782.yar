rule TTP_XOR_WriteProcessMemory_c782 {
  strings:
    $key_c782 = { 90 f0 [2] a2 d2 [2] a4 e7 [2] 8a e7 [2] b5 fb }

  condition:
    any of them
}