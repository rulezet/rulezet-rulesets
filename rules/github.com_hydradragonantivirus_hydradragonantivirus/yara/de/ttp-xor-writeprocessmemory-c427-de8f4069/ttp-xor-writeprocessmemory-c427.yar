rule TTP_XOR_WriteProcessMemory_c427 {
  strings:
    $key_c427 = { 93 55 [2] a1 77 [2] a7 42 [2] 89 42 [2] b6 5e }

  condition:
    any of them
}