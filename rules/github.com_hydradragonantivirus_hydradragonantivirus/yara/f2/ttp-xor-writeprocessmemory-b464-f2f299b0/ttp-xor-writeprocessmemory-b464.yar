rule TTP_XOR_WriteProcessMemory_b464 {
  strings:
    $key_b464 = { e3 16 [2] d1 34 [2] d7 01 [2] f9 01 [2] c6 1d }

  condition:
    any of them
}