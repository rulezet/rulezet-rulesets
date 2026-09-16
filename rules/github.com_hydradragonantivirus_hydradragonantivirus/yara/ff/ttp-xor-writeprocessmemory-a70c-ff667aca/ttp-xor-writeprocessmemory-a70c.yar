rule TTP_XOR_WriteProcessMemory_a70c {
  strings:
    $key_a70c = { f0 7e [2] c2 5c [2] c4 69 [2] ea 69 [2] d5 75 }

  condition:
    any of them
}