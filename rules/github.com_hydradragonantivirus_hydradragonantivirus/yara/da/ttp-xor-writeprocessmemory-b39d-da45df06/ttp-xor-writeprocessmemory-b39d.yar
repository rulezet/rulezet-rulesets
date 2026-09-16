rule TTP_XOR_WriteProcessMemory_b39d {
  strings:
    $key_b39d = { e4 ef [2] d6 cd [2] d0 f8 [2] fe f8 [2] c1 e4 }

  condition:
    any of them
}