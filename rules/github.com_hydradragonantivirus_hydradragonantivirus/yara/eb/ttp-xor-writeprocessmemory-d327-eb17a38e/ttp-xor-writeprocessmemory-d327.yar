rule TTP_XOR_WriteProcessMemory_d327 {
  strings:
    $key_d327 = { 84 55 [2] b6 77 [2] b0 42 [2] 9e 42 [2] a1 5e }

  condition:
    any of them
}