rule TTP_XOR_WriteProcessMemory_d737 {
  strings:
    $key_d737 = { 80 45 [2] b2 67 [2] b4 52 [2] 9a 52 [2] a5 4e }

  condition:
    any of them
}