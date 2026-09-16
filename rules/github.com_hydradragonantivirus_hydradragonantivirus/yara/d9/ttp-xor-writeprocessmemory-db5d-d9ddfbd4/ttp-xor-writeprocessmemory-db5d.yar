rule TTP_XOR_WriteProcessMemory_db5d {
  strings:
    $key_db5d = { 8c 2f [2] be 0d [2] b8 38 [2] 96 38 [2] a9 24 }

  condition:
    any of them
}