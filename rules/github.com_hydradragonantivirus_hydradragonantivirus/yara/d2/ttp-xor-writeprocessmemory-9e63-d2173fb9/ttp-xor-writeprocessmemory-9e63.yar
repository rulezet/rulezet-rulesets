rule TTP_XOR_WriteProcessMemory_9e63 {
  strings:
    $key_9e63 = { c9 11 [2] fb 33 [2] fd 06 [2] d3 06 [2] ec 1a }

  condition:
    any of them
}