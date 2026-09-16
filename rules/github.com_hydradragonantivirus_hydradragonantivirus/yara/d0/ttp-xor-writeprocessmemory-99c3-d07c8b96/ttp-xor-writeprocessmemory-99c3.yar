rule TTP_XOR_WriteProcessMemory_99c3 {
  strings:
    $key_99c3 = { ce b1 [2] fc 93 [2] fa a6 [2] d4 a6 [2] eb ba }

  condition:
    any of them
}