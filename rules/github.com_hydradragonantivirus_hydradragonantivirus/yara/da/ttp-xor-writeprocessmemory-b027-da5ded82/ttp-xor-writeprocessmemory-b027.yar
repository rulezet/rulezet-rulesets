rule TTP_XOR_WriteProcessMemory_b027 {
  strings:
    $key_b027 = { e7 55 [2] d5 77 [2] d3 42 [2] fd 42 [2] c2 5e }

  condition:
    any of them
}