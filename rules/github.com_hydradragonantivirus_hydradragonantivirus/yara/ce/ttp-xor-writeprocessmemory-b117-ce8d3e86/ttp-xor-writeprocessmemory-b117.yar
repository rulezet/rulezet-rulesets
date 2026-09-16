rule TTP_XOR_WriteProcessMemory_b117 {
  strings:
    $key_b117 = { e6 65 [2] d4 47 [2] d2 72 [2] fc 72 [2] c3 6e }

  condition:
    any of them
}