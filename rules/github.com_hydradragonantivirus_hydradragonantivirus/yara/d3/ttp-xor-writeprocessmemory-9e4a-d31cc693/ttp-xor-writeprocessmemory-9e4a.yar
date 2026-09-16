rule TTP_XOR_WriteProcessMemory_9e4a {
  strings:
    $key_9e4a = { c9 38 [2] fb 1a [2] fd 2f [2] d3 2f [2] ec 33 }

  condition:
    any of them
}