rule TTP_XOR_WriteProcessMemory_b140 {
  strings:
    $key_b140 = { e6 32 [2] d4 10 [2] d2 25 [2] fc 25 [2] c3 39 }

  condition:
    any of them
}