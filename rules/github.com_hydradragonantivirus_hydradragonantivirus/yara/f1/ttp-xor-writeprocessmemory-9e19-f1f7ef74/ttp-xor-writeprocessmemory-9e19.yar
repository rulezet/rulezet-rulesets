rule TTP_XOR_WriteProcessMemory_9e19 {
  strings:
    $key_9e19 = { c9 6b [2] fb 49 [2] fd 7c [2] d3 7c [2] ec 60 }

  condition:
    any of them
}