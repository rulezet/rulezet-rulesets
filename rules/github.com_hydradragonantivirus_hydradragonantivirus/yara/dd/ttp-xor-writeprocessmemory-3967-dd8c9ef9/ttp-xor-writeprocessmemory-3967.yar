rule TTP_XOR_WriteProcessMemory_3967 {
  strings:
    $key_3967 = { 6e 15 [2] 5c 37 [2] 5a 02 [2] 74 02 [2] 4b 1e }

  condition:
    any of them
}