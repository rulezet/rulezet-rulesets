rule TTP_XOR_WriteProcessMemory_b473 {
  strings:
    $key_b473 = { e3 01 [2] d1 23 [2] d7 16 [2] f9 16 [2] c6 0a }

  condition:
    any of them
}