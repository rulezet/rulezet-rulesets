rule TTP_XOR_WriteProcessMemory_b479 {
  strings:
    $key_b479 = { e3 0b [2] d1 29 [2] d7 1c [2] f9 1c [2] c6 00 }

  condition:
    any of them
}