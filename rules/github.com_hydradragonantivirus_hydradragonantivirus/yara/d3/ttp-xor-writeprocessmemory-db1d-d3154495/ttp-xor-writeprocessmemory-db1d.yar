rule TTP_XOR_WriteProcessMemory_db1d {
  strings:
    $key_db1d = { 8c 6f [2] be 4d [2] b8 78 [2] 96 78 [2] a9 64 }

  condition:
    any of them
}