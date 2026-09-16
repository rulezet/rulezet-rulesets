rule TTP_XOR_WriteProcessMemory_c162 {
  strings:
    $key_c162 = { 96 10 [2] a4 32 [2] a2 07 [2] 8c 07 [2] b3 1b }

  condition:
    any of them
}