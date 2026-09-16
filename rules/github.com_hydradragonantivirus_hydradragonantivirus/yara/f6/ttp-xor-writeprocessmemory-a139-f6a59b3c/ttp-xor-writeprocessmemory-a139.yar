rule TTP_XOR_WriteProcessMemory_a139 {
  strings:
    $key_a139 = { f6 4b [2] c4 69 [2] c2 5c [2] ec 5c [2] d3 40 }

  condition:
    any of them
}