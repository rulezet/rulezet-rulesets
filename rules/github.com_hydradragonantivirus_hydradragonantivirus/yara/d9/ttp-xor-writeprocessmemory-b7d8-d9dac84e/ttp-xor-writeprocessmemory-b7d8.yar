rule TTP_XOR_WriteProcessMemory_b7d8 {
  strings:
    $key_b7d8 = { e0 aa [2] d2 88 [2] d4 bd [2] fa bd [2] c5 a1 }

  condition:
    any of them
}