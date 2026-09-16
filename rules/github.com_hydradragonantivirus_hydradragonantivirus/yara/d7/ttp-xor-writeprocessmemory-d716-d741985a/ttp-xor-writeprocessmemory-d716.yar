rule TTP_XOR_WriteProcessMemory_d716 {
  strings:
    $key_d716 = { 80 64 [2] b2 46 [2] b4 73 [2] 9a 73 [2] a5 6f }

  condition:
    any of them
}