rule TTP_XOR_WriteProcessMemory_a2b7 {
  strings:
    $key_a2b7 = { f5 c5 [2] c7 e7 [2] c1 d2 [2] ef d2 [2] d0 ce }

  condition:
    any of them
}