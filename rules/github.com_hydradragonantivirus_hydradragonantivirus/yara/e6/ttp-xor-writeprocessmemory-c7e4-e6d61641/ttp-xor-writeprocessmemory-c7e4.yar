rule TTP_XOR_WriteProcessMemory_c7e4 {
  strings:
    $key_c7e4 = { 90 96 [2] a2 b4 [2] a4 81 [2] 8a 81 [2] b5 9d }

  condition:
    any of them
}