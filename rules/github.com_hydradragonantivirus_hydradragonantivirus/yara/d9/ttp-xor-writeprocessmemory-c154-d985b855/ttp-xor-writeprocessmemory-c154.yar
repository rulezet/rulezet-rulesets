rule TTP_XOR_WriteProcessMemory_c154 {
  strings:
    $key_c154 = { 96 26 [2] a4 04 [2] a2 31 [2] 8c 31 [2] b3 2d }

  condition:
    any of them
}