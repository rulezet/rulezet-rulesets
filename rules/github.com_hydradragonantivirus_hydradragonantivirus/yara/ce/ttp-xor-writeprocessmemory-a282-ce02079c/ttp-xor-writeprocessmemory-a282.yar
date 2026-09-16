rule TTP_XOR_WriteProcessMemory_a282 {
  strings:
    $key_a282 = { f5 f0 [2] c7 d2 [2] c1 e7 [2] ef e7 [2] d0 fb }

  condition:
    any of them
}