rule TTP_XOR_WriteProcessMemory_c967 {
  strings:
    $key_c967 = { 9e 15 [2] ac 37 [2] aa 02 [2] 84 02 [2] bb 1e }

  condition:
    any of them
}