rule TTP_XOR_WriteProcessMemory_db03 {
  strings:
    $key_db03 = { 8c 71 [2] be 53 [2] b8 66 [2] 96 66 [2] a9 7a }

  condition:
    any of them
}