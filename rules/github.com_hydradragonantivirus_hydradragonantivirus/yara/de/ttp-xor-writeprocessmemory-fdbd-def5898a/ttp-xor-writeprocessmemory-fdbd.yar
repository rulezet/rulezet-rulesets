rule TTP_XOR_WriteProcessMemory_fdbd {
  strings:
    $key_fdbd = { aa cf [2] 98 ed [2] 9e d8 [2] b0 d8 [2] 8f c4 }

  condition:
    any of them
}