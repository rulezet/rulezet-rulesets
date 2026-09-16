rule TTP_XOR_WriteProcessMemory_a090 {
  strings:
    $key_a090 = { f7 e2 [2] c5 c0 [2] c3 f5 [2] ed f5 [2] d2 e9 }

  condition:
    any of them
}