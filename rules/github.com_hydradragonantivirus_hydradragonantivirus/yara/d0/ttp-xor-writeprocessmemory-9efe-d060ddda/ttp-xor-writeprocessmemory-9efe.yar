rule TTP_XOR_WriteProcessMemory_9efe {
  strings:
    $key_9efe = { c9 8c [2] fb ae [2] fd 9b [2] d3 9b [2] ec 87 }

  condition:
    any of them
}