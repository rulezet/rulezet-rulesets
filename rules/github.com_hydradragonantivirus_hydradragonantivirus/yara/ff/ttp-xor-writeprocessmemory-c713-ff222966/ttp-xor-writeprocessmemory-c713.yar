rule TTP_XOR_WriteProcessMemory_c713 {
  strings:
    $key_c713 = { 90 61 [2] a2 43 [2] a4 76 [2] 8a 76 [2] b5 6a }

  condition:
    any of them
}