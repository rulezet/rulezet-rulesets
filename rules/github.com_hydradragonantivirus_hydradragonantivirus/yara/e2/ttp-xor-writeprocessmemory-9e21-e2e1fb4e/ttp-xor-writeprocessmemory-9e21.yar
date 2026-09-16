rule TTP_XOR_WriteProcessMemory_9e21 {
  strings:
    $key_9e21 = { c9 53 [2] fb 71 [2] fd 44 [2] d3 44 [2] ec 58 }

  condition:
    any of them
}