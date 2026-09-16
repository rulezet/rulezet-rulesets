rule TTP_XOR_WriteProcessMemory_9ee9 {
  strings:
    $key_9ee9 = { c9 9b [2] fb b9 [2] fd 8c [2] d3 8c [2] ec 90 }

  condition:
    any of them
}