rule TTP_XOR_WriteProcessMemory_98b6 {
  strings:
    $key_98b6 = { cf c4 [2] fd e6 [2] fb d3 [2] d5 d3 [2] ea cf }

  condition:
    any of them
}