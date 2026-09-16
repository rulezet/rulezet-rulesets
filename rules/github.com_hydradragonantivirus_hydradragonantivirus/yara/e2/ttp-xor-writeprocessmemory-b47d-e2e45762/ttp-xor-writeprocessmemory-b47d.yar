rule TTP_XOR_WriteProcessMemory_b47d {
  strings:
    $key_b47d = { e3 0f [2] d1 2d [2] d7 18 [2] f9 18 [2] c6 04 }

  condition:
    any of them
}