rule TTP_XOR_WriteProcessMemory_a160 {
  strings:
    $key_a160 = { f6 12 [2] c4 30 [2] c2 05 [2] ec 05 [2] d3 19 }

  condition:
    any of them
}