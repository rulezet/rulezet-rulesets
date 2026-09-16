rule TTP_XOR_WriteProcessMemory_6713 {
  strings:
    $key_6713 = { 30 61 [2] 02 43 [2] 04 76 [2] 2a 76 [2] 15 6a }

  condition:
    any of them
}