rule TTP_XOR_WriteProcessMemory_7ebd {
  strings:
    $key_7ebd = { 29 cf [2] 1b ed [2] 1d d8 [2] 33 d8 [2] 0c c4 }

  condition:
    any of them
}