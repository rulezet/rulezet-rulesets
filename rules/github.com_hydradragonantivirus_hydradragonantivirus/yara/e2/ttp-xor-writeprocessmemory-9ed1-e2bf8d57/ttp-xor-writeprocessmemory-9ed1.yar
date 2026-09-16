rule TTP_XOR_WriteProcessMemory_9ed1 {
  strings:
    $key_9ed1 = { c9 a3 [2] fb 81 [2] fd b4 [2] d3 b4 [2] ec a8 }

  condition:
    any of them
}