rule TTP_XOR_WriteProcessMemory_a76e {
  strings:
    $key_a76e = { f0 1c [2] c2 3e [2] c4 0b [2] ea 0b [2] d5 17 }

  condition:
    any of them
}