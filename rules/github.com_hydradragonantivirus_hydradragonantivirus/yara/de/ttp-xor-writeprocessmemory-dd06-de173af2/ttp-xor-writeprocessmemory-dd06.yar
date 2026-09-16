rule TTP_XOR_WriteProcessMemory_dd06 {
  strings:
    $key_dd06 = { 8a 74 [2] b8 56 [2] be 63 [2] 90 63 [2] af 7f }

  condition:
    any of them
}