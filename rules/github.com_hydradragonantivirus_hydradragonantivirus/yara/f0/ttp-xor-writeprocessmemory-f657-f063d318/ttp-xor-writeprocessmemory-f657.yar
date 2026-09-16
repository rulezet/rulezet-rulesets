rule TTP_XOR_WriteProcessMemory_f657 {
  strings:
    $key_f657 = { a1 25 [2] 93 07 [2] 95 32 [2] bb 32 [2] 84 2e }

  condition:
    any of them
}