rule TTP_XOR_WriteProcessMemory_b77d {
  strings:
    $key_b77d = { e0 0f [2] d2 2d [2] d4 18 [2] fa 18 [2] c5 04 }

  condition:
    any of them
}