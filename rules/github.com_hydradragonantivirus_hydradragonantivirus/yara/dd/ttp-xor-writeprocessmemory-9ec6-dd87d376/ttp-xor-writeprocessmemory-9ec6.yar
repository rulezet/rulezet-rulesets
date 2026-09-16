rule TTP_XOR_WriteProcessMemory_9ec6 {
  strings:
    $key_9ec6 = { c9 b4 [2] fb 96 [2] fd a3 [2] d3 a3 [2] ec bf }

  condition:
    any of them
}