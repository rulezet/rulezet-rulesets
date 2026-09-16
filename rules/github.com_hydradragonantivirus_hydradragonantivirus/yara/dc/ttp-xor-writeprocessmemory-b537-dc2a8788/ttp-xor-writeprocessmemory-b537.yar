rule TTP_XOR_WriteProcessMemory_b537 {
  strings:
    $key_b537 = { e2 45 [2] d0 67 [2] d6 52 [2] f8 52 [2] c7 4e }

  condition:
    any of them
}