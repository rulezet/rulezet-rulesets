rule TTP_XOR_WriteProcessMemory_debd {
  strings:
    $key_debd = { 89 cf [2] bb ed [2] bd d8 [2] 93 d8 [2] ac c4 }

  condition:
    any of them
}