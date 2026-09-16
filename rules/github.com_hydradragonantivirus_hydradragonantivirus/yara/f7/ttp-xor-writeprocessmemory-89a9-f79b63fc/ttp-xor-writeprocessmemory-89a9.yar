rule TTP_XOR_WriteProcessMemory_89a9 {
  strings:
    $key_89a9 = { de db [2] ec f9 [2] ea cc [2] c4 cc [2] fb d0 }

  condition:
    any of them
}