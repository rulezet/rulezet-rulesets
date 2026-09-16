rule TTP_XOR_WriteProcessMemory_b3fc {
  strings:
    $key_b3fc = { e4 8e [2] d6 ac [2] d0 99 [2] fe 99 [2] c1 85 }

  condition:
    any of them
}