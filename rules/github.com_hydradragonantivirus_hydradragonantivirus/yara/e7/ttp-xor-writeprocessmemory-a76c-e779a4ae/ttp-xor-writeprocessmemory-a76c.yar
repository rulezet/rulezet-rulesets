rule TTP_XOR_WriteProcessMemory_a76c {
  strings:
    $key_a76c = { f0 1e [2] c2 3c [2] c4 09 [2] ea 09 [2] d5 15 }

  condition:
    any of them
}