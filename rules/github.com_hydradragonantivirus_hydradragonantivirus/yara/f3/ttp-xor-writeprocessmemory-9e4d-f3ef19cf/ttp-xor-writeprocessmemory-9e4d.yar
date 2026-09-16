rule TTP_XOR_WriteProcessMemory_9e4d {
  strings:
    $key_9e4d = { c9 3f [2] fb 1d [2] fd 28 [2] d3 28 [2] ec 34 }

  condition:
    any of them
}