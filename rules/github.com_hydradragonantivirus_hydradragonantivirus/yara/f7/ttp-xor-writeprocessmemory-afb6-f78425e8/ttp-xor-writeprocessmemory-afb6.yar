rule TTP_XOR_WriteProcessMemory_afb6 {
  strings:
    $key_afb6 = { f8 c4 [2] ca e6 [2] cc d3 [2] e2 d3 [2] dd cf }

  condition:
    any of them
}