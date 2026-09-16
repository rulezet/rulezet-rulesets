rule TTP_XOR_WriteProcessMemory_a79d {
  strings:
    $key_a79d = { f0 ef [2] c2 cd [2] c4 f8 [2] ea f8 [2] d5 e4 }

  condition:
    any of them
}