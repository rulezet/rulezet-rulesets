rule TTP_XOR_WriteProcessMemory_89a6 {
  strings:
    $key_89a6 = { de d4 [2] ec f6 [2] ea c3 [2] c4 c3 [2] fb df }

  condition:
    any of them
}