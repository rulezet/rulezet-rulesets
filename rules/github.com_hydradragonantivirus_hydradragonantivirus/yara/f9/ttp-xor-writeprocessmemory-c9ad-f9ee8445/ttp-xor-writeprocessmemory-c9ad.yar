rule TTP_XOR_WriteProcessMemory_c9ad {
  strings:
    $key_c9ad = { 9e df [2] ac fd [2] aa c8 [2] 84 c8 [2] bb d4 }

  condition:
    any of them
}