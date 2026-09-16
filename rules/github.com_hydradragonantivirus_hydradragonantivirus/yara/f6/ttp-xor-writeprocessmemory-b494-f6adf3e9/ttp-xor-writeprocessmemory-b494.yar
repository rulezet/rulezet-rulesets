rule TTP_XOR_WriteProcessMemory_b494 {
  strings:
    $key_b494 = { e3 e6 [2] d1 c4 [2] d7 f1 [2] f9 f1 [2] c6 ed }

  condition:
    any of them
}