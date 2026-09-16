rule TTP_XOR_WriteProcessMemory_90bd {
  strings:
    $key_90bd = { c7 cf [2] f5 ed [2] f3 d8 [2] dd d8 [2] e2 c4 }

  condition:
    any of them
}