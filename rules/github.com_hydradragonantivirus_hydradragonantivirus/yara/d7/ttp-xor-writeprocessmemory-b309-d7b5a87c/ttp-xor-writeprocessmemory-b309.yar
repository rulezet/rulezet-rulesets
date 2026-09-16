rule TTP_XOR_WriteProcessMemory_b309 {
  strings:
    $key_b309 = { e4 7b [2] d6 59 [2] d0 6c [2] fe 6c [2] c1 70 }

  condition:
    any of them
}