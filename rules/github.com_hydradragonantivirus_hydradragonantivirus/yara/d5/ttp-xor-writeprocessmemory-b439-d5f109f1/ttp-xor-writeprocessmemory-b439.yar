rule TTP_XOR_WriteProcessMemory_b439 {
  strings:
    $key_b439 = { e3 4b [2] d1 69 [2] d7 5c [2] f9 5c [2] c6 40 }

  condition:
    any of them
}