rule TTP_XOR_WriteProcessMemory_d427 {
  strings:
    $key_d427 = { 83 55 [2] b1 77 [2] b7 42 [2] 99 42 [2] a6 5e }

  condition:
    any of them
}