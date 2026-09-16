rule TTP_XOR_WriteProcessMemory_d557 {
  strings:
    $key_d557 = { 82 25 [2] b0 07 [2] b6 32 [2] 98 32 [2] a7 2e }

  condition:
    any of them
}