rule TTP_XOR_WriteProcessMemory_db21 {
  strings:
    $key_db21 = { 8c 53 [2] be 71 [2] b8 44 [2] 96 44 [2] a9 58 }

  condition:
    any of them
}