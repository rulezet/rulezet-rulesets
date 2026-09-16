rule TTP_XOR_WriteProcessMemory_a05c {
  strings:
    $key_a05c = { f7 2e [2] c5 0c [2] c3 39 [2] ed 39 [2] d2 25 }

  condition:
    any of them
}