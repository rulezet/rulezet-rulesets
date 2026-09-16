rule TTP_XOR_WriteProcessMemory_db32 {
  strings:
    $key_db32 = { 8c 40 [2] be 62 [2] b8 57 [2] 96 57 [2] a9 4b }

  condition:
    any of them
}