rule TTP_XOR_WriteProcessMemory_9ebd {
  strings:
    $key_9ebd = { c9 cf [2] fb ed [2] fd d8 [2] d3 d8 [2] ec c4 }

  condition:
    any of them
}