rule TTP_XOR_WriteProcessMemory_c541 {
  strings:
    $key_c541 = { 92 33 [2] a0 11 [2] a6 24 [2] 88 24 [2] b7 38 }

  condition:
    any of them
}