rule TTP_XOR_WriteProcessMemory_d457 {
  strings:
    $key_d457 = { 83 25 [2] b1 07 [2] b7 32 [2] 99 32 [2] a6 2e }

  condition:
    any of them
}