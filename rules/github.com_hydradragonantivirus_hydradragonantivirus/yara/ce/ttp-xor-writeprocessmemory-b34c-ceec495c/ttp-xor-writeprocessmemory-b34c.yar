rule TTP_XOR_WriteProcessMemory_b34c {
  strings:
    $key_b34c = { e4 3e [2] d6 1c [2] d0 29 [2] fe 29 [2] c1 35 }

  condition:
    any of them
}