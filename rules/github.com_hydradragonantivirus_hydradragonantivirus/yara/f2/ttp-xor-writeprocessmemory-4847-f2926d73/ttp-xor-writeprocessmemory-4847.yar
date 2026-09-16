rule TTP_XOR_WriteProcessMemory_4847 {
  strings:
    $key_4847 = { 1f 35 [2] 2d 17 [2] 2b 22 [2] 05 22 [2] 3a 3e }

  condition:
    any of them
}