rule TTP_XOR_WriteProcessMemory_b4ed {
  strings:
    $key_b4ed = { e3 9f [2] d1 bd [2] d7 88 [2] f9 88 [2] c6 94 }

  condition:
    any of them
}