rule TTP_XOR_WriteProcessMemory_9e47 {
  strings:
    $key_9e47 = { c9 35 [2] fb 17 [2] fd 22 [2] d3 22 [2] ec 3e }

  condition:
    any of them
}