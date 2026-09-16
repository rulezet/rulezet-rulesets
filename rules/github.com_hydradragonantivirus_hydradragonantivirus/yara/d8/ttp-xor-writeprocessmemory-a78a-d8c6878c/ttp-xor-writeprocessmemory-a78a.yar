rule TTP_XOR_WriteProcessMemory_a78a {
  strings:
    $key_a78a = { f0 f8 [2] c2 da [2] c4 ef [2] ea ef [2] d5 f3 }

  condition:
    any of them
}