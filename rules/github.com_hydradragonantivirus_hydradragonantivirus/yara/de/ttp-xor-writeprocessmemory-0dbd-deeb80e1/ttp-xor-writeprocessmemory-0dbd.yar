rule TTP_XOR_WriteProcessMemory_0dbd {
  strings:
    $key_0dbd = { 5a cf [2] 68 ed [2] 6e d8 [2] 40 d8 [2] 7f c4 }

  condition:
    any of them
}