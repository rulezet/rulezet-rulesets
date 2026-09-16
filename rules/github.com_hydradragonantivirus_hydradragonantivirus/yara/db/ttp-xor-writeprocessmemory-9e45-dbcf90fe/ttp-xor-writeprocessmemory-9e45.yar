rule TTP_XOR_WriteProcessMemory_9e45 {
  strings:
    $key_9e45 = { c9 37 [2] fb 15 [2] fd 20 [2] d3 20 [2] ec 3c }

  condition:
    any of them
}