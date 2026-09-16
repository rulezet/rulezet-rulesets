rule TTP_XOR_WriteProcessMemory_a4ed {
  strings:
    $key_a4ed = { f3 9f [2] c1 bd [2] c7 88 [2] e9 88 [2] d6 94 }

  condition:
    any of them
}