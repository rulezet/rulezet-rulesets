rule TTP_XOR_WriteProcessMemory_c537 {
  strings:
    $key_c537 = { 92 45 [2] a0 67 [2] a6 52 [2] 88 52 [2] b7 4e }

  condition:
    any of them
}