rule TTP_XOR_WriteProcessMemory_a417 {
  strings:
    $key_a417 = { f3 65 [2] c1 47 [2] c7 72 [2] e9 72 [2] d6 6e }

  condition:
    any of them
}