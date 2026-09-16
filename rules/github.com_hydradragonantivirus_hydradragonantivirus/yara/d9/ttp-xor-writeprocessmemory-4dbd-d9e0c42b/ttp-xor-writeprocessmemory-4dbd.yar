rule TTP_XOR_WriteProcessMemory_4dbd {
  strings:
    $key_4dbd = { 1a cf [2] 28 ed [2] 2e d8 [2] 00 d8 [2] 3f c4 }

  condition:
    any of them
}