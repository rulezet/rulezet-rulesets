rule TTP_XOR_WriteProcessMemory_c547 {
  strings:
    $key_c547 = { 92 35 [2] a0 17 [2] a6 22 [2] 88 22 [2] b7 3e }

  condition:
    any of them
}