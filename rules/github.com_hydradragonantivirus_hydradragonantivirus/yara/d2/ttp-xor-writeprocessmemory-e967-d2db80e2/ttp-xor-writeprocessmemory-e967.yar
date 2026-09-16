rule TTP_XOR_WriteProcessMemory_e967 {
  strings:
    $key_e967 = { be 15 [2] 8c 37 [2] 8a 02 [2] a4 02 [2] 9b 1e }

  condition:
    any of them
}