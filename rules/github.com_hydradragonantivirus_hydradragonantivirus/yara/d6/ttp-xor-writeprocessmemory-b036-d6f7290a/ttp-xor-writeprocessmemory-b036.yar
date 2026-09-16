rule TTP_XOR_WriteProcessMemory_b036 {
  strings:
    $key_b036 = { e7 44 [2] d5 66 [2] d3 53 [2] fd 53 [2] c2 4f }

  condition:
    any of them
}