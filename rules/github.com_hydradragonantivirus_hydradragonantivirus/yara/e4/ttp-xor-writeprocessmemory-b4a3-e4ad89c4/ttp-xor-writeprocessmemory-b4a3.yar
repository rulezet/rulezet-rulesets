rule TTP_XOR_WriteProcessMemory_b4a3 {
  strings:
    $key_b4a3 = { e3 d1 [2] d1 f3 [2] d7 c6 [2] f9 c6 [2] c6 da }

  condition:
    any of them
}