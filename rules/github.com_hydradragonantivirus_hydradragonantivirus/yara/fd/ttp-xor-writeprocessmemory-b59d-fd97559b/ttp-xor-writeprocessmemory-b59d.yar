rule TTP_XOR_WriteProcessMemory_b59d {
  strings:
    $key_b59d = { e2 ef [2] d0 cd [2] d6 f8 [2] f8 f8 [2] c7 e4 }

  condition:
    any of them
}