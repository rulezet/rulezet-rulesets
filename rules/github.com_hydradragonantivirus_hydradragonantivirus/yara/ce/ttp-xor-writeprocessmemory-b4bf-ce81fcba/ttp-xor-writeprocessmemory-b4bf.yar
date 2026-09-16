rule TTP_XOR_WriteProcessMemory_b4bf {
  strings:
    $key_b4bf = { e3 cd [2] d1 ef [2] d7 da [2] f9 da [2] c6 c6 }

  condition:
    any of them
}