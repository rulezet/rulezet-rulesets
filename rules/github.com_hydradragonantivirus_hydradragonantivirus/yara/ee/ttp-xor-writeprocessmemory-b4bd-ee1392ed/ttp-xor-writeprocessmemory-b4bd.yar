rule TTP_XOR_WriteProcessMemory_b4bd {
  strings:
    $key_b4bd = { e3 cf [2] d1 ed [2] d7 d8 [2] f9 d8 [2] c6 c4 }

  condition:
    any of them
}