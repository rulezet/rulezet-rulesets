rule TTP_XOR_WriteProcessMemory_a7d8 {
  strings:
    $key_a7d8 = { f0 aa [2] c2 88 [2] c4 bd [2] ea bd [2] d5 a1 }

  condition:
    any of them
}