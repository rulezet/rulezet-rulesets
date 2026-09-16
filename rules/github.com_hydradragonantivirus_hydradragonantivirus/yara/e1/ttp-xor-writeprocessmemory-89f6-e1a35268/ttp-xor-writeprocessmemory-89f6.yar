rule TTP_XOR_WriteProcessMemory_89f6 {
  strings:
    $key_89f6 = { de 84 [2] ec a6 [2] ea 93 [2] c4 93 [2] fb 8f }

  condition:
    any of them
}