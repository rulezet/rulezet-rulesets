rule TTP_XOR_WriteProcessMemory_a7bf {
  strings:
    $key_a7bf = { f0 cd [2] c2 ef [2] c4 da [2] ea da [2] d5 c6 }

  condition:
    any of them
}