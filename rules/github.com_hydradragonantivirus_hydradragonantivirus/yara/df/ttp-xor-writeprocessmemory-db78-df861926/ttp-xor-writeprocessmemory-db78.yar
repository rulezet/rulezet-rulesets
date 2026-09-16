rule TTP_XOR_WriteProcessMemory_db78 {
  strings:
    $key_db78 = { 8c 0a [2] be 28 [2] b8 1d [2] 96 1d [2] a9 01 }

  condition:
    any of them
}