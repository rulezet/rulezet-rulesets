rule TTP_XOR_WriteProcessMemory_0bbd {
  strings:
    $key_0bbd = { 5c cf [2] 6e ed [2] 68 d8 [2] 46 d8 [2] 79 c4 }

  condition:
    any of them
}