rule TTP_XOR_WriteProcessMemory_9e14 {
  strings:
    $key_9e14 = { c9 66 [2] fb 44 [2] fd 71 [2] d3 71 [2] ec 6d }

  condition:
    any of them
}