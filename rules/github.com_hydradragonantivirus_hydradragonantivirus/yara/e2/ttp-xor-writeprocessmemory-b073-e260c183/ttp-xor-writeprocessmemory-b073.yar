rule TTP_XOR_WriteProcessMemory_b073 {
  strings:
    $key_b073 = { e7 01 [2] d5 23 [2] d3 16 [2] fd 16 [2] c2 0a }

  condition:
    any of them
}