rule TTP_XOR_WriteProcessMemory_dd43 {
  strings:
    $key_dd43 = { 8a 31 [2] b8 13 [2] be 26 [2] 90 26 [2] af 3a }

  condition:
    any of them
}