rule TTP_XOR_WriteProcessMemory_b069 {
  strings:
    $key_b069 = { e7 1b [2] d5 39 [2] d3 0c [2] fd 0c [2] c2 10 }

  condition:
    any of them
}