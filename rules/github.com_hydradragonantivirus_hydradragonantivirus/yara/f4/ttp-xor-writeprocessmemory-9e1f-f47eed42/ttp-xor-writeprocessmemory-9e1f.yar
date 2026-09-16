rule TTP_XOR_WriteProcessMemory_9e1f {
  strings:
    $key_9e1f = { c9 6d [2] fb 4f [2] fd 7a [2] d3 7a [2] ec 66 }

  condition:
    any of them
}