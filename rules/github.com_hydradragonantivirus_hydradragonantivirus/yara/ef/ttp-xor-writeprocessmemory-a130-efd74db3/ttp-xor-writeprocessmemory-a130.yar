rule TTP_XOR_WriteProcessMemory_a130 {
  strings:
    $key_a130 = { f6 42 [2] c4 60 [2] c2 55 [2] ec 55 [2] d3 49 }

  condition:
    any of them
}