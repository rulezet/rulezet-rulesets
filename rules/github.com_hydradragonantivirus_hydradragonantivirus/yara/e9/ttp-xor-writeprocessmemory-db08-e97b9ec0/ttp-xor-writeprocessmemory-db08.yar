rule TTP_XOR_WriteProcessMemory_db08 {
  strings:
    $key_db08 = { 8c 7a [2] be 58 [2] b8 6d [2] 96 6d [2] a9 71 }

  condition:
    any of them
}