rule TTP_XOR_WriteProcessMemory_dbd7 {
  strings:
    $key_dbd7 = { 8c a5 [2] be 87 [2] b8 b2 [2] 96 b2 [2] a9 ae }

  condition:
    any of them
}