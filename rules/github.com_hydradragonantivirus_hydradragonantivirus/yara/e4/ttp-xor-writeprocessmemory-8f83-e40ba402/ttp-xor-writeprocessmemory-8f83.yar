rule TTP_XOR_WriteProcessMemory_8f83 {
  strings:
    $key_8f83 = { d8 f1 [2] ea d3 [2] ec e6 [2] c2 e6 [2] fd fa }

  condition:
    any of them
}