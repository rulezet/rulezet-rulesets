rule TTP_XOR_WriteProcessMemory_b4e4 {
  strings:
    $key_b4e4 = { e3 96 [2] d1 b4 [2] d7 81 [2] f9 81 [2] c6 9d }

  condition:
    any of them
}