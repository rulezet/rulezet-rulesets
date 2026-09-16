rule TTP_XOR_WriteProcessMemory_a5d8 {
  strings:
    $key_a5d8 = { f2 aa [2] c0 88 [2] c6 bd [2] e8 bd [2] d7 a1 }

  condition:
    any of them
}