rule TTP_XOR_WriteProcessMemory_aca1 {
  strings:
    $key_aca1 = { fb d3 [2] c9 f1 [2] cf c4 [2] e1 c4 [2] de d8 }

  condition:
    any of them
}