rule TTP_XOR_WriteProcessMemory_a020 {
  strings:
    $key_a020 = { f7 52 [2] c5 70 [2] c3 45 [2] ed 45 [2] d2 59 }

  condition:
    any of them
}