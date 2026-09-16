rule TTP_XOR_WriteProcessMemory_a061 {
  strings:
    $key_a061 = { f7 13 [2] c5 31 [2] c3 04 [2] ed 04 [2] d2 18 }

  condition:
    any of them
}