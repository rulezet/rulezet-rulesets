rule TTP_XOR_WriteProcessMemory_b107 {
  strings:
    $key_b107 = { e6 75 [2] d4 57 [2] d2 62 [2] fc 62 [2] c3 7e }

  condition:
    any of them
}