rule TTP_XOR_WriteProcessMemory_89a3 {
  strings:
    $key_89a3 = { de d1 [2] ec f3 [2] ea c6 [2] c4 c6 [2] fb da }

  condition:
    any of them
}