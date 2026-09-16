rule TTP_XOR_WriteProcessMemory_9e1e {
  strings:
    $key_9e1e = { c9 6c [2] fb 4e [2] fd 7b [2] d3 7b [2] ec 67 }

  condition:
    any of them
}