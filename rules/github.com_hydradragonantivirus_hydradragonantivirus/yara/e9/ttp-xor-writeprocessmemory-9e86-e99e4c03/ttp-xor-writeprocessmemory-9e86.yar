rule TTP_XOR_WriteProcessMemory_9e86 {
  strings:
    $key_9e86 = { c9 f4 [2] fb d6 [2] fd e3 [2] d3 e3 [2] ec ff }

  condition:
    any of them
}