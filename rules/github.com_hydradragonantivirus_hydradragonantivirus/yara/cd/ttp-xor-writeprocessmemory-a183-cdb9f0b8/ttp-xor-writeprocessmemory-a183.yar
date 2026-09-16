rule TTP_XOR_WriteProcessMemory_a183 {
  strings:
    $key_a183 = { f6 f1 [2] c4 d3 [2] c2 e6 [2] ec e6 [2] d3 fa }

  condition:
    any of them
}