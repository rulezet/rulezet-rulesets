rule TTP_XOR_WriteProcessMemory_9e93 {
  strings:
    $key_9e93 = { c9 e1 [2] fb c3 [2] fd f6 [2] d3 f6 [2] ec ea }

  condition:
    any of them
}