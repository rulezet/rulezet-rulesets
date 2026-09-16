rule TTP_XOR_WriteProcessMemory_2267 {
  strings:
    $key_2267 = { 75 15 [2] 47 37 [2] 41 02 [2] 6f 02 [2] 50 1e }

  condition:
    any of them
}