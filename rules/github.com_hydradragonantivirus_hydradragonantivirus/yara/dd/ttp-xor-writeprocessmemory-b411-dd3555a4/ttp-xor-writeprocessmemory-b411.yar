rule TTP_XOR_WriteProcessMemory_b411 {
  strings:
    $key_b411 = { e3 63 [2] d1 41 [2] d7 74 [2] f9 74 [2] c6 68 }

  condition:
    any of them
}