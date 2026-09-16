rule TTP_XOR_WriteProcessMemory_b054 {
  strings:
    $key_b054 = { e7 26 [2] d5 04 [2] d3 31 [2] fd 31 [2] c2 2d }

  condition:
    any of them
}