rule TTP_XOR_WriteProcessMemory_d127 {
  strings:
    $key_d127 = { 86 55 [2] b4 77 [2] b2 42 [2] 9c 42 [2] a3 5e }

  condition:
    any of them
}