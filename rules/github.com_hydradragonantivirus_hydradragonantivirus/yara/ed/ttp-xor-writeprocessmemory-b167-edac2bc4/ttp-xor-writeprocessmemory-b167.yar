rule TTP_XOR_WriteProcessMemory_b167 {
  strings:
    $key_b167 = { e6 15 [2] d4 37 [2] d2 02 [2] fc 02 [2] c3 1e }

  condition:
    any of them
}