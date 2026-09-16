rule TTP_XOR_WriteProcessMemory_9ed6 {
  strings:
    $key_9ed6 = { c9 a4 [2] fb 86 [2] fd b3 [2] d3 b3 [2] ec af }

  condition:
    any of them
}