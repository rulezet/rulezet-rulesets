rule TTP_XOR_WriteProcessMemory_0ebd {
  strings:
    $key_0ebd = { 59 cf [2] 6b ed [2] 6d d8 [2] 43 d8 [2] 7c c4 }

  condition:
    any of them
}