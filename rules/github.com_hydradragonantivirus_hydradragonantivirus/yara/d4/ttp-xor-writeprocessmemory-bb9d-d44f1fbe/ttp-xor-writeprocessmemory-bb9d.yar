rule TTP_XOR_WriteProcessMemory_bb9d {
  strings:
    $key_bb9d = { ec ef [2] de cd [2] d8 f8 [2] f6 f8 [2] c9 e4 }

  condition:
    any of them
}