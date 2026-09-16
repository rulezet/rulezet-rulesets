rule TTP_XOR_WriteProcessMemory_4bbd {
  strings:
    $key_4bbd = { 1c cf [2] 2e ed [2] 28 d8 [2] 06 d8 [2] 39 c4 }

  condition:
    any of them
}