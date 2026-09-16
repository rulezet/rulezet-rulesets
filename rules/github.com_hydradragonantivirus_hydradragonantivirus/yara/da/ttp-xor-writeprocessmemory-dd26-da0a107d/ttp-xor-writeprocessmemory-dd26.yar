rule TTP_XOR_WriteProcessMemory_dd26 {
  strings:
    $key_dd26 = { 8a 54 [2] b8 76 [2] be 43 [2] 90 43 [2] af 5f }

  condition:
    any of them
}