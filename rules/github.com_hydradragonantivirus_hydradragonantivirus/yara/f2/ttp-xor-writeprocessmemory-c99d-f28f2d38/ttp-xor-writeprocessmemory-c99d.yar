rule TTP_XOR_WriteProcessMemory_c99d {
  strings:
    $key_c99d = { 9e ef [2] ac cd [2] aa f8 [2] 84 f8 [2] bb e4 }

  condition:
    any of them
}