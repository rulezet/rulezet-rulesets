rule TTP_XOR_WriteProcessMemory_db02 {
  strings:
    $key_db02 = { 8c 70 [2] be 52 [2] b8 67 [2] 96 67 [2] a9 7b }

  condition:
    any of them
}