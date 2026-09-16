rule TTP_XOR_WriteProcessMemory_cda0 {
  strings:
    $key_cda0 = { 9a d2 [2] a8 f0 [2] ae c5 [2] 80 c5 [2] bf d9 }

  condition:
    any of them
}