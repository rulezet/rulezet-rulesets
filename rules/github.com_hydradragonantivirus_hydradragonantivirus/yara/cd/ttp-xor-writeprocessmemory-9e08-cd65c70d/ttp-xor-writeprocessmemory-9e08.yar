rule TTP_XOR_WriteProcessMemory_9e08 {
  strings:
    $key_9e08 = { c9 7a [2] fb 58 [2] fd 6d [2] d3 6d [2] ec 71 }

  condition:
    any of them
}