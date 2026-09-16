rule TTP_XOR_WriteProcessMemory_9e2c {
  strings:
    $key_9e2c = { c9 5e [2] fb 7c [2] fd 49 [2] d3 49 [2] ec 55 }

  condition:
    any of them
}