rule TTP_XOR_WriteProcessMemory_b5bd {
  strings:
    $key_b5bd = { e2 cf [2] d0 ed [2] d6 d8 [2] f8 d8 [2] c7 c4 }

  condition:
    any of them
}