rule TTP_XOR_WriteProcessMemory_a1f8 {
  strings:
    $key_a1f8 = { f6 8a [2] c4 a8 [2] c2 9d [2] ec 9d [2] d3 81 }

  condition:
    any of them
}