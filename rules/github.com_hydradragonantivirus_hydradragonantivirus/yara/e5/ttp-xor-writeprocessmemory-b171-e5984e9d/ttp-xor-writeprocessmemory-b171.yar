rule TTP_XOR_WriteProcessMemory_b171 {
  strings:
    $key_b171 = { e6 03 [2] d4 21 [2] d2 14 [2] fc 14 [2] c3 08 }

  condition:
    any of them
}