rule TTP_XOR_WriteProcessMemory_a16b {
  strings:
    $key_a16b = { f6 19 [2] c4 3b [2] c2 0e [2] ec 0e [2] d3 12 }

  condition:
    any of them
}