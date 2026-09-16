rule TTP_XOR_WriteProcessMemory_9e9b {
  strings:
    $key_9e9b = { c9 e9 [2] fb cb [2] fd fe [2] d3 fe [2] ec e2 }

  condition:
    any of them
}