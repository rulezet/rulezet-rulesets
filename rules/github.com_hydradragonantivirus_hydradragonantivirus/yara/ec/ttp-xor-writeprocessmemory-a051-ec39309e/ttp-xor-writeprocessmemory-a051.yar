rule TTP_XOR_WriteProcessMemory_a051 {
  strings:
    $key_a051 = { f7 23 [2] c5 01 [2] c3 34 [2] ed 34 [2] d2 28 }

  condition:
    any of them
}