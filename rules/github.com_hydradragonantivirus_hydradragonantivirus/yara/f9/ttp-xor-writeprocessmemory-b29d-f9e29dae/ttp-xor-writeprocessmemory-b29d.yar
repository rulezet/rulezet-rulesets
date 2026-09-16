rule TTP_XOR_WriteProcessMemory_b29d {
  strings:
    $key_b29d = { e5 ef [2] d7 cd [2] d1 f8 [2] ff f8 [2] c0 e4 }

  condition:
    any of them
}