rule TTP_XOR_WriteProcessMemory_9ea9 {
  strings:
    $key_9ea9 = { c9 db [2] fb f9 [2] fd cc [2] d3 cc [2] ec d0 }

  condition:
    any of them
}