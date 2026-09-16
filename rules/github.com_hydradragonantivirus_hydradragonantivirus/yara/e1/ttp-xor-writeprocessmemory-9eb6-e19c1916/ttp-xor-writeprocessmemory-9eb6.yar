rule TTP_XOR_WriteProcessMemory_9eb6 {
  strings:
    $key_9eb6 = { c9 c4 [2] fb e6 [2] fd d3 [2] d3 d3 [2] ec cf }

  condition:
    any of them
}