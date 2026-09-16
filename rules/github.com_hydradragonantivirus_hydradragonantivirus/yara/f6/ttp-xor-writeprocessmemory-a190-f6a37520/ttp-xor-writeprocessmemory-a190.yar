rule TTP_XOR_WriteProcessMemory_a190 {
  strings:
    $key_a190 = { f6 e2 [2] c4 c0 [2] c2 f5 [2] ec f5 [2] d3 e9 }

  condition:
    any of them
}