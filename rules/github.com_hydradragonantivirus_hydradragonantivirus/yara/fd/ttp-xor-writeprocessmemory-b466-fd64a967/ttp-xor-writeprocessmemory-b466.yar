rule TTP_XOR_WriteProcessMemory_b466 {
  strings:
    $key_b466 = { e3 14 [2] d1 36 [2] d7 03 [2] f9 03 [2] c6 1f }

  condition:
    any of them
}