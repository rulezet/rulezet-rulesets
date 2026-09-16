rule TTP_XOR_WriteProcessMemory_b469 {
  strings:
    $key_b469 = { e3 1b [2] d1 39 [2] d7 0c [2] f9 0c [2] c6 10 }

  condition:
    any of them
}