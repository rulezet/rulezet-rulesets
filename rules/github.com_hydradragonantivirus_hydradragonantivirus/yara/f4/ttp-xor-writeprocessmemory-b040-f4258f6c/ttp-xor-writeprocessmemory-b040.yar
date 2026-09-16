rule TTP_XOR_WriteProcessMemory_b040 {
  strings:
    $key_b040 = { e7 32 [2] d5 10 [2] d3 25 [2] fd 25 [2] c2 39 }

  condition:
    any of them
}