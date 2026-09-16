rule TTP_XOR_WriteProcessMemory_a18e {
  strings:
    $key_a18e = { f6 fc [2] c4 de [2] c2 eb [2] ec eb [2] d3 f7 }

  condition:
    any of them
}