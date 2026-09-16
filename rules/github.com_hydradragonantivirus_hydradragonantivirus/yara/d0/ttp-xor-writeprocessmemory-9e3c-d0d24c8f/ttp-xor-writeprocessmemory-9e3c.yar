rule TTP_XOR_WriteProcessMemory_9e3c {
  strings:
    $key_9e3c = { c9 4e [2] fb 6c [2] fd 59 [2] d3 59 [2] ec 45 }

  condition:
    any of them
}