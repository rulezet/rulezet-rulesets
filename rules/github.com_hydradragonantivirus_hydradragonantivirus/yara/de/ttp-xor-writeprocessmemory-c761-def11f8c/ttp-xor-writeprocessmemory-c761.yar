rule TTP_XOR_WriteProcessMemory_c761 {
  strings:
    $key_c761 = { 90 13 [2] a2 31 [2] a4 04 [2] 8a 04 [2] b5 18 }

  condition:
    any of them
}