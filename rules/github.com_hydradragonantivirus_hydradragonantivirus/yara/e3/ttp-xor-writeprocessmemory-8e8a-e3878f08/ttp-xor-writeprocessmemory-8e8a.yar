rule TTP_XOR_WriteProcessMemory_8e8a {
  strings:
    $key_8e8a = { d9 f8 [2] eb da [2] ed ef [2] c3 ef [2] fc f3 }

  condition:
    any of them
}