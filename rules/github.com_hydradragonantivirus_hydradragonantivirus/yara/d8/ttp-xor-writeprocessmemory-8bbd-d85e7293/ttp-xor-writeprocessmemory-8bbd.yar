rule TTP_XOR_WriteProcessMemory_8bbd {
  strings:
    $key_8bbd = { dc cf [2] ee ed [2] e8 d8 [2] c6 d8 [2] f9 c4 }

  condition:
    any of them
}