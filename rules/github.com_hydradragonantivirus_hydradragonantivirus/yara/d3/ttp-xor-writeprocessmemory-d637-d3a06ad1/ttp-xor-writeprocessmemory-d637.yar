rule TTP_XOR_WriteProcessMemory_d637 {
  strings:
    $key_d637 = { 81 45 [2] b3 67 [2] b5 52 [2] 9b 52 [2] a4 4e }

  condition:
    any of them
}