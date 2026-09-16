rule TTP_XOR_WriteProcessMemory_b0d3 {
  strings:
    $key_b0d3 = { e7 a1 [2] d5 83 [2] d3 b6 [2] fd b6 [2] c2 aa }

  condition:
    any of them
}