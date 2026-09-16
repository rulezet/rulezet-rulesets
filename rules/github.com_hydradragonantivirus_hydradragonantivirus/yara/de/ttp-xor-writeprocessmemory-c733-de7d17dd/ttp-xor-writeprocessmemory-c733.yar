rule TTP_XOR_WriteProcessMemory_c733 {
  strings:
    $key_c733 = { 90 41 [2] a2 63 [2] a4 56 [2] 8a 56 [2] b5 4a }

  condition:
    any of them
}