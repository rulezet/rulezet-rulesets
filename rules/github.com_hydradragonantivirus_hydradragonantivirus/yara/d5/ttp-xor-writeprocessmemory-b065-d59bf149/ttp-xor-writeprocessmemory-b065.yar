rule TTP_XOR_WriteProcessMemory_b065 {
  strings:
    $key_b065 = { e7 17 [2] d5 35 [2] d3 00 [2] fd 00 [2] c2 1c }

  condition:
    any of them
}