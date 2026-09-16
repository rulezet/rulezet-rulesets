rule TTP_XOR_WriteProcessMemory_b7e3 {
  strings:
    $key_b7e3 = { e0 91 [2] d2 b3 [2] d4 86 [2] fa 86 [2] c5 9a }

  condition:
    any of them
}