rule TTP_XOR_WriteProcessMemory_e912 {
  strings:
    $key_e912 = { be 60 [2] 8c 42 [2] 8a 77 [2] a4 77 [2] 9b 6b }

  condition:
    any of them
}