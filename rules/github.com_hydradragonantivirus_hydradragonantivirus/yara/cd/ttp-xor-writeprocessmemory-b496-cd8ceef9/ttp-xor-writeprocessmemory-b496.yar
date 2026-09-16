rule TTP_XOR_WriteProcessMemory_b496 {
  strings:
    $key_b496 = { e3 e4 [2] d1 c6 [2] d7 f3 [2] f9 f3 [2] c6 ef }

  condition:
    any of them
}