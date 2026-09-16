rule TTP_XOR_WriteProcessMemory_9e53 {
  strings:
    $key_9e53 = { c9 21 [2] fb 03 [2] fd 36 [2] d3 36 [2] ec 2a }

  condition:
    any of them
}