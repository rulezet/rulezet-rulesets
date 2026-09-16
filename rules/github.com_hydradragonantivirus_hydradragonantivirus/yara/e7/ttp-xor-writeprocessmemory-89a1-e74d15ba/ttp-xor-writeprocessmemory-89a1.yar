rule TTP_XOR_WriteProcessMemory_89a1 {
  strings:
    $key_89a1 = { de d3 [2] ec f1 [2] ea c4 [2] c4 c4 [2] fb d8 }

  condition:
    any of them
}