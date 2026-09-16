rule TTP_XOR_WriteProcessMemory_9e0c {
  strings:
    $key_9e0c = { c9 7e [2] fb 5c [2] fd 69 [2] d3 69 [2] ec 75 }

  condition:
    any of them
}