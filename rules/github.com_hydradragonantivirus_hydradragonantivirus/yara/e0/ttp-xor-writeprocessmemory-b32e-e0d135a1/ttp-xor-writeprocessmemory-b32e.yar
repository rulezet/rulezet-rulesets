rule TTP_XOR_WriteProcessMemory_b32e {
  strings:
    $key_b32e = { e4 5c [2] d6 7e [2] d0 4b [2] fe 4b [2] c1 57 }

  condition:
    any of them
}