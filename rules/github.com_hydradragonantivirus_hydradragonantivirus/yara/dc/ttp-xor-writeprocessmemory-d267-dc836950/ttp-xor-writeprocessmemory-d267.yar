rule TTP_XOR_WriteProcessMemory_d267 {
  strings:
    $key_d267 = { 85 15 [2] b7 37 [2] b1 02 [2] 9f 02 [2] a0 1e }

  condition:
    any of them
}