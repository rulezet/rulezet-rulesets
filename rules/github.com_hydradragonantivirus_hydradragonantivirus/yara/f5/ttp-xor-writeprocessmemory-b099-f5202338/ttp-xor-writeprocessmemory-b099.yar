rule TTP_XOR_WriteProcessMemory_b099 {
  strings:
    $key_b099 = { e7 eb [2] d5 c9 [2] d3 fc [2] fd fc [2] c2 e0 }

  condition:
    any of them
}