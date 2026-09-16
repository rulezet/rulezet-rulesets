rule TTP_XOR_WriteProcessMemory_dd42 {
  strings:
    $key_dd42 = { 8a 30 [2] b8 12 [2] be 27 [2] 90 27 [2] af 3b }

  condition:
    any of them
}