rule TTP_XOR_WriteProcessMemory_6726 {
  strings:
    $key_6726 = { 30 54 [2] 02 76 [2] 04 43 [2] 2a 43 [2] 15 5f }

  condition:
    any of them
}