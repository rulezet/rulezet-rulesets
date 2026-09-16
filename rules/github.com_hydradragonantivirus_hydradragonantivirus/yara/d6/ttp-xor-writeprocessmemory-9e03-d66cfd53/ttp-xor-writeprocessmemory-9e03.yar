rule TTP_XOR_WriteProcessMemory_9e03 {
  strings:
    $key_9e03 = { c9 71 [2] fb 53 [2] fd 66 [2] d3 66 [2] ec 7a }

  condition:
    any of them
}