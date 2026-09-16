rule TTP_XOR_WriteProcessMemory_c0e4 {
  strings:
    $key_c0e4 = { 97 96 [2] a5 b4 [2] a3 81 [2] 8d 81 [2] b2 9d }

  condition:
    any of them
}