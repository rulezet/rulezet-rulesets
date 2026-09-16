rule TTP_XOR_WriteProcessMemory_dd73 {
  strings:
    $key_dd73 = { 8a 01 [2] b8 23 [2] be 16 [2] 90 16 [2] af 0a }

  condition:
    any of them
}