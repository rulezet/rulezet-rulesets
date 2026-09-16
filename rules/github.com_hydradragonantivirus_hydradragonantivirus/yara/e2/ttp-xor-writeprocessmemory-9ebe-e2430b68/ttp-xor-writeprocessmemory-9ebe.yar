rule TTP_XOR_WriteProcessMemory_9ebe {
  strings:
    $key_9ebe = { c9 cc [2] fb ee [2] fd db [2] d3 db [2] ec c7 }

  condition:
    any of them
}