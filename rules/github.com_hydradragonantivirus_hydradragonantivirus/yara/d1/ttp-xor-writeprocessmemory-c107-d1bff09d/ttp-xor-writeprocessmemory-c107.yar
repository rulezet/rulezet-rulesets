rule TTP_XOR_WriteProcessMemory_c107 {
  strings:
    $key_c107 = { 96 75 [2] a4 57 [2] a2 62 [2] 8c 62 [2] b3 7e }

  condition:
    any of them
}