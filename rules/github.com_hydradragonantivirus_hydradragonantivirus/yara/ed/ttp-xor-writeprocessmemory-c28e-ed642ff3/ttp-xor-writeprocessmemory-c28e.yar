rule TTP_XOR_WriteProcessMemory_c28e {
  strings:
    $key_c28e = { 95 fc [2] a7 de [2] a1 eb [2] 8f eb [2] b0 f7 }

  condition:
    any of them
}