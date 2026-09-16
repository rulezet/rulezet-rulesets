rule TTP_XOR_WriteProcessMemory_edbd {
  strings:
    $key_edbd = { ba cf [2] 88 ed [2] 8e d8 [2] a0 d8 [2] 9f c4 }

  condition:
    any of them
}