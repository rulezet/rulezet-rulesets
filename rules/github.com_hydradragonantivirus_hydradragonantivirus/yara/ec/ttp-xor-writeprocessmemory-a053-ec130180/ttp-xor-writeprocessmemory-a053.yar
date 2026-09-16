rule TTP_XOR_WriteProcessMemory_a053 {
  strings:
    $key_a053 = { f7 21 [2] c5 03 [2] c3 36 [2] ed 36 [2] d2 2a }

  condition:
    any of them
}