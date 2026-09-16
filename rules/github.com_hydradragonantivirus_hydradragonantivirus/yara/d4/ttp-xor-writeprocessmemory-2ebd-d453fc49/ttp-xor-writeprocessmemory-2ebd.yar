rule TTP_XOR_WriteProcessMemory_2ebd {
  strings:
    $key_2ebd = { 79 cf [2] 4b ed [2] 4d d8 [2] 63 d8 [2] 5c c4 }

  condition:
    any of them
}