rule TTP_XOR_WriteProcessMemory_e932 {
  strings:
    $key_e932 = { be 40 [2] 8c 62 [2] 8a 57 [2] a4 57 [2] 9b 4b }

  condition:
    any of them
}