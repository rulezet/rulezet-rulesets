rule TTP_XOR_WriteProcessMemory_0aad {
  strings:
    $key_0aad = { 5d df [2] 6f fd [2] 69 c8 [2] 47 c8 [2] 78 d4 }

  condition:
    any of them
}