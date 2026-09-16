rule TTP_XOR_WriteProcessMemory_a493 {
  strings:
    $key_a493 = { f3 e1 [2] c1 c3 [2] c7 f6 [2] e9 f6 [2] d6 ea }

  condition:
    any of them
}