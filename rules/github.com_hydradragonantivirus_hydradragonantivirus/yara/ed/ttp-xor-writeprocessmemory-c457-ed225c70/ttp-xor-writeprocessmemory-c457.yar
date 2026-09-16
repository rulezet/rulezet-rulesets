rule TTP_XOR_WriteProcessMemory_c457 {
  strings:
    $key_c457 = { 93 25 [2] a1 07 [2] a7 32 [2] 89 32 [2] b6 2e }

  condition:
    any of them
}