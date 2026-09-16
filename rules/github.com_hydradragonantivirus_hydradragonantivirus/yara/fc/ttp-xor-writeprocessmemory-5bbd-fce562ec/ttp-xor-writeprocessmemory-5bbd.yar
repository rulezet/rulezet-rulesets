rule TTP_XOR_WriteProcessMemory_5bbd {
  strings:
    $key_5bbd = { 0c cf [2] 3e ed [2] 38 d8 [2] 16 d8 [2] 29 c4 }

  condition:
    any of them
}