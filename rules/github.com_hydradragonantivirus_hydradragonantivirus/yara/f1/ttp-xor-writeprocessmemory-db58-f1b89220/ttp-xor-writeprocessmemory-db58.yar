rule TTP_XOR_WriteProcessMemory_db58 {
  strings:
    $key_db58 = { 8c 2a [2] be 08 [2] b8 3d [2] 96 3d [2] a9 21 }

  condition:
    any of them
}