rule TTP_XOR_WriteProcessMemory_c1ed {
  strings:
    $key_c1ed = { 96 9f [2] a4 bd [2] a2 88 [2] 8c 88 [2] b3 94 }

  condition:
    any of them
}