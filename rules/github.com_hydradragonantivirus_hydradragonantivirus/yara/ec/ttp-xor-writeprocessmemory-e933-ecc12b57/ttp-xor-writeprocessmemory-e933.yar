rule TTP_XOR_WriteProcessMemory_e933 {
  strings:
    $key_e933 = { be 41 [2] 8c 63 [2] 8a 56 [2] a4 56 [2] 9b 4a }

  condition:
    any of them
}