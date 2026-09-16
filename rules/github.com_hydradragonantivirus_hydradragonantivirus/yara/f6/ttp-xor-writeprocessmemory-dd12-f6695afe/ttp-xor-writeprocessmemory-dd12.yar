rule TTP_XOR_WriteProcessMemory_dd12 {
  strings:
    $key_dd12 = { 8a 60 [2] b8 42 [2] be 77 [2] 90 77 [2] af 6b }

  condition:
    any of them
}