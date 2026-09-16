rule TTP_XOR_WriteProcessMemory_dbe6 {
  strings:
    $key_dbe6 = { 8c 94 [2] be b6 [2] b8 83 [2] 96 83 [2] a9 9f }

  condition:
    any of them
}