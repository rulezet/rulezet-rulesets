rule TTP_XOR_WriteProcessMemory_a114 {
  strings:
    $key_a114 = { f6 66 [2] c4 44 [2] c2 71 [2] ec 71 [2] d3 6d }

  condition:
    any of them
}