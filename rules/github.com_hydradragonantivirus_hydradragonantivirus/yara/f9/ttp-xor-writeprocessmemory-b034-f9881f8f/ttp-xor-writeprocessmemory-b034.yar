rule TTP_XOR_WriteProcessMemory_b034 {
  strings:
    $key_b034 = { e7 46 [2] d5 64 [2] d3 51 [2] fd 51 [2] c2 4d }

  condition:
    any of them
}