rule TTP_XOR_WriteProcessMemory_a011 {
  strings:
    $key_a011 = { f7 63 [2] c5 41 [2] c3 74 [2] ed 74 [2] d2 68 }

  condition:
    any of them
}