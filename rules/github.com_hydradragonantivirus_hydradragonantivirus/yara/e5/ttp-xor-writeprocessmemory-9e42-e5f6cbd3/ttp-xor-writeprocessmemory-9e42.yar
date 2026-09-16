rule TTP_XOR_WriteProcessMemory_9e42 {
  strings:
    $key_9e42 = { c9 30 [2] fb 12 [2] fd 27 [2] d3 27 [2] ec 3b }

  condition:
    any of them
}