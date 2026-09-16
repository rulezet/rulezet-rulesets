rule TTP_XOR_WriteProcessMemory_fedd {
  strings:
    $key_fedd = { a9 af [2] 9b 8d [2] 9d b8 [2] b3 b8 [2] 8c a4 }

  condition:
    any of them
}