rule TTP_XOR_WriteProcessMemory_d727 {
  strings:
    $key_d727 = { 80 55 [2] b2 77 [2] b4 42 [2] 9a 42 [2] a5 5e }

  condition:
    any of them
}