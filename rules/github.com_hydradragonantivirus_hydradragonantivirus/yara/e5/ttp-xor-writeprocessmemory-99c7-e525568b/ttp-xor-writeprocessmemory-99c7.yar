rule TTP_XOR_WriteProcessMemory_99c7 {
  strings:
    $key_99c7 = { ce b5 [2] fc 97 [2] fa a2 [2] d4 a2 [2] eb be }

  condition:
    any of them
}