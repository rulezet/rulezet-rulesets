rule TTP_XOR_WriteProcessMemory_2a67 {
  strings:
    $key_2a67 = { 7d 15 [2] 4f 37 [2] 49 02 [2] 67 02 [2] 58 1e }

  condition:
    any of them
}