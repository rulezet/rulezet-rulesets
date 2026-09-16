rule TTP_XOR_WriteProcessMemory_c5d7 {
  strings:
    $key_c5d7 = { 92 a5 [2] a0 87 [2] a6 b2 [2] 88 b2 [2] b7 ae }

  condition:
    any of them
}