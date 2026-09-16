rule TTP_XOR_WriteProcessMemory_849d {
  strings:
    $key_849d = { d3 ef [2] e1 cd [2] e7 f8 [2] c9 f8 [2] f6 e4 }

  condition:
    any of them
}