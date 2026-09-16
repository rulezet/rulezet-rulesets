rule TTP_XOR_WriteProcessMemory_c593 {
  strings:
    $key_c593 = { 92 e1 [2] a0 c3 [2] a6 f6 [2] 88 f6 [2] b7 ea }

  condition:
    any of them
}