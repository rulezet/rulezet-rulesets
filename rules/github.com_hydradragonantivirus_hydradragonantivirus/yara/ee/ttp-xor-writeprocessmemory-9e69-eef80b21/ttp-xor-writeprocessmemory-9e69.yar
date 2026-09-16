rule TTP_XOR_WriteProcessMemory_9e69 {
  strings:
    $key_9e69 = { c9 1b [2] fb 39 [2] fd 0c [2] d3 0c [2] ec 10 }

  condition:
    any of them
}