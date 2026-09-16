rule TTP_XOR_WriteProcessMemory_b40c {
  strings:
    $key_b40c = { e3 7e [2] d1 5c [2] d7 69 [2] f9 69 [2] c6 75 }

  condition:
    any of them
}