rule TTP_XOR_WriteProcessMemory_dbbd {
  strings:
    $key_dbbd = { 8c cf [2] be ed [2] b8 d8 [2] 96 d8 [2] a9 c4 }

  condition:
    any of them
}