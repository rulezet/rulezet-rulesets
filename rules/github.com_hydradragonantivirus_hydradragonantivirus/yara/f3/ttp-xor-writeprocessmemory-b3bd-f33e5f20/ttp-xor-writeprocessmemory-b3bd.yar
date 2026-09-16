rule TTP_XOR_WriteProcessMemory_b3bd {
  strings:
    $key_b3bd = { e4 cf [2] d6 ed [2] d0 d8 [2] fe d8 [2] c1 c4 }

  condition:
    any of them
}