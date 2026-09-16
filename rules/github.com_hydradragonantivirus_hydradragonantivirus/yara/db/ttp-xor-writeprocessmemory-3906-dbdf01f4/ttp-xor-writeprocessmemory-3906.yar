rule TTP_XOR_WriteProcessMemory_3906 {
  strings:
    $key_3906 = { 6e 74 [2] 5c 56 [2] 5a 63 [2] 74 63 [2] 4b 7f }

  condition:
    any of them
}