rule TTP_XOR_WriteProcessMemory_9e40 {
  strings:
    $key_9e40 = { c9 32 [2] fb 10 [2] fd 25 [2] d3 25 [2] ec 39 }

  condition:
    any of them
}