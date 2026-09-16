rule TTP_XOR_WriteProcessMemory_9e83 {
  strings:
    $key_9e83 = { c9 f1 [2] fb d3 [2] fd e6 [2] d3 e6 [2] ec fa }

  condition:
    any of them
}