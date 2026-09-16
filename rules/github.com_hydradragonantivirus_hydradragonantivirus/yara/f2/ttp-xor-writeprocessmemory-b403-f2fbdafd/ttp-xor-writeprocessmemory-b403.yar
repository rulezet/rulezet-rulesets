rule TTP_XOR_WriteProcessMemory_b403 {
  strings:
    $key_b403 = { e3 71 [2] d1 53 [2] d7 66 [2] f9 66 [2] c6 7a }

  condition:
    any of them
}