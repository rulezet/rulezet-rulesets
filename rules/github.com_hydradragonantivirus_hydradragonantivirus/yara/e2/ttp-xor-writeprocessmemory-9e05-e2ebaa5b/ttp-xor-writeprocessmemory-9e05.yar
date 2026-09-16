rule TTP_XOR_WriteProcessMemory_9e05 {
  strings:
    $key_9e05 = { c9 77 [2] fb 55 [2] fd 60 [2] d3 60 [2] ec 7c }

  condition:
    any of them
}