rule TTP_XOR_WriteProcessMemory_cc41 {
  strings:
    $key_cc41 = { 9b 33 [2] a9 11 [2] af 24 [2] 81 24 [2] be 38 }

  condition:
    any of them
}