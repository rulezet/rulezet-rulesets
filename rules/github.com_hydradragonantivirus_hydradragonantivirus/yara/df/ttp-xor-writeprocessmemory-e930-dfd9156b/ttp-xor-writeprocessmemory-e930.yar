rule TTP_XOR_WriteProcessMemory_e930 {
  strings:
    $key_e930 = { be 42 [2] 8c 60 [2] 8a 55 [2] a4 55 [2] 9b 49 }

  condition:
    any of them
}