rule TTP_XOR_WriteProcessMemory_cbbd {
  strings:
    $key_cbbd = { 9c cf [2] ae ed [2] a8 d8 [2] 86 d8 [2] b9 c4 }

  condition:
    any of them
}