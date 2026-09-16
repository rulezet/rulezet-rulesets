rule TTP_XOR_WriteProcessMemory_9e1c {
  strings:
    $key_9e1c = { c9 6e [2] fb 4c [2] fd 79 [2] d3 79 [2] ec 65 }

  condition:
    any of them
}