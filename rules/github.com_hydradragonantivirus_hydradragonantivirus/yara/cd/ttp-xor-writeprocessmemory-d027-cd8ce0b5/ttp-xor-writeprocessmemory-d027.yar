rule TTP_XOR_WriteProcessMemory_d027 {
  strings:
    $key_d027 = { 87 55 [2] b5 77 [2] b3 42 [2] 9d 42 [2] a2 5e }

  condition:
    any of them
}