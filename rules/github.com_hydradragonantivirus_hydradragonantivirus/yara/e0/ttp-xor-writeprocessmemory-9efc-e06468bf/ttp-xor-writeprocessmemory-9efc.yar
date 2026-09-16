rule TTP_XOR_WriteProcessMemory_9efc {
  strings:
    $key_9efc = { c9 8e [2] fb ac [2] fd 99 [2] d3 99 [2] ec 85 }

  condition:
    any of them
}