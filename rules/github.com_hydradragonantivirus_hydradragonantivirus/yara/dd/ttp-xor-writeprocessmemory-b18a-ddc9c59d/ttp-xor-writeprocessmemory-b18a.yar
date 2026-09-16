rule TTP_XOR_WriteProcessMemory_b18a {
  strings:
    $key_b18a = { e6 f8 [2] d4 da [2] d2 ef [2] fc ef [2] c3 f3 }

  condition:
    any of them
}