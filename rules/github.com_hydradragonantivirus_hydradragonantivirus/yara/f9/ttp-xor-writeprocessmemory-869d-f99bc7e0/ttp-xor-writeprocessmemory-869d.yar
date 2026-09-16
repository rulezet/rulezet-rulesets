rule TTP_XOR_WriteProcessMemory_869d {
  strings:
    $key_869d = { d1 ef [2] e3 cd [2] e5 f8 [2] cb f8 [2] f4 e4 }

  condition:
    any of them
}