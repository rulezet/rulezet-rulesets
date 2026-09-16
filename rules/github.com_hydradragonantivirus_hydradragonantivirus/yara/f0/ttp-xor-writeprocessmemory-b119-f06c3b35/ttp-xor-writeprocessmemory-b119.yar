rule TTP_XOR_WriteProcessMemory_b119 {
  strings:
    $key_b119 = { e6 6b [2] d4 49 [2] d2 7c [2] fc 7c [2] c3 60 }

  condition:
    any of them
}