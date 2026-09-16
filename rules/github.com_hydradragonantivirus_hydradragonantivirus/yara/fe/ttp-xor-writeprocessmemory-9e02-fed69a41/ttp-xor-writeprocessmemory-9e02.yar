rule TTP_XOR_WriteProcessMemory_9e02 {
  strings:
    $key_9e02 = { c9 70 [2] fb 52 [2] fd 67 [2] d3 67 [2] ec 7b }

  condition:
    any of them
}