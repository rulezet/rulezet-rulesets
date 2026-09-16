rule TTP_XOR_WriteProcessMemory_ccf2 {
  strings:
    $key_ccf2 = { 9b 80 [2] a9 a2 [2] af 97 [2] 81 97 [2] be 8b }

  condition:
    any of them
}