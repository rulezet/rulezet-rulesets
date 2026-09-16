rule TTP_XOR_WriteProcessMemory_9ede {
  strings:
    $key_9ede = { c9 ac [2] fb 8e [2] fd bb [2] d3 bb [2] ec a7 }

  condition:
    any of them
}