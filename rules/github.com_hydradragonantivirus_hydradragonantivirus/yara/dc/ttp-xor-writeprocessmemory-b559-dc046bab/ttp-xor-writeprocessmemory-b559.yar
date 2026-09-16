rule TTP_XOR_WriteProcessMemory_b559 {
  strings:
    $key_b559 = { e2 2b [2] d0 09 [2] d6 3c [2] f8 3c [2] c7 20 }

  condition:
    any of them
}