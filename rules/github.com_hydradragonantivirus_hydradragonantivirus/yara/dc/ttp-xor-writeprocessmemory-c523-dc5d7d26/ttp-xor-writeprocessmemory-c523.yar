rule TTP_XOR_WriteProcessMemory_c523 {
  strings:
    $key_c523 = { 92 51 [2] a0 73 [2] a6 46 [2] 88 46 [2] b7 5a }

  condition:
    any of them
}