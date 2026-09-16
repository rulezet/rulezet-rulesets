rule TTP_XOR_WriteProcessMemory_dbb9 {
  strings:
    $key_dbb9 = { 8c cb [2] be e9 [2] b8 dc [2] 96 dc [2] a9 c0 }

  condition:
    any of them
}