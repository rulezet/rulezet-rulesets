rule TTP_XOR_WriteProcessMemory_89bd {
  strings:
    $key_89bd = { de cf [2] ec ed [2] ea d8 [2] c4 d8 [2] fb c4 }

  condition:
    any of them
}