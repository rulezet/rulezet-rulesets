rule TTP_XOR_WriteProcessMemory_b5bf {
  strings:
    $key_b5bf = { e2 cd [2] d0 ef [2] d6 da [2] f8 da [2] c7 c6 }

  condition:
    any of them
}