rule TTP_XOR_WriteProcessMemory_9e29 {
  strings:
    $key_9e29 = { c9 5b [2] fb 79 [2] fd 4c [2] d3 4c [2] ec 50 }

  condition:
    any of them
}