rule TTP_XOR_WriteProcessMemory_a06c {
  strings:
    $key_a06c = { f7 1e [2] c5 3c [2] c3 09 [2] ed 09 [2] d2 15 }

  condition:
    any of them
}