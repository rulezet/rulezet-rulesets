rule TTP_XOR_WriteProcessMemory_99c2 {
  strings:
    $key_99c2 = { ce b0 [2] fc 92 [2] fa a7 [2] d4 a7 [2] eb bb }

  condition:
    any of them
}