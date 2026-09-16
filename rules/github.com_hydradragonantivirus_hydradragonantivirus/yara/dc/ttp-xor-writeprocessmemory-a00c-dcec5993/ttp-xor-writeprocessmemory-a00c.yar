rule TTP_XOR_WriteProcessMemory_a00c {
  strings:
    $key_a00c = { f7 7e [2] c5 5c [2] c3 69 [2] ed 69 [2] d2 75 }

  condition:
    any of them
}