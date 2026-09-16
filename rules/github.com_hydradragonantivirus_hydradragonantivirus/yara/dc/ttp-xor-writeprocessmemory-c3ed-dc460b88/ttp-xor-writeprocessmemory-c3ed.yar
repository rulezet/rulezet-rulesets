rule TTP_XOR_WriteProcessMemory_c3ed {
  strings:
    $key_c3ed = { 94 9f [2] a6 bd [2] a0 88 [2] 8e 88 [2] b1 94 }

  condition:
    any of them
}