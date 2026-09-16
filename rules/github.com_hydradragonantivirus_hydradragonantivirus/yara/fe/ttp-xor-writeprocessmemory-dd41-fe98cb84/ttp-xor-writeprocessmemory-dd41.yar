rule TTP_XOR_WriteProcessMemory_dd41 {
  strings:
    $key_dd41 = { 8a 33 [2] b8 11 [2] be 24 [2] 90 24 [2] af 38 }

  condition:
    any of them
}