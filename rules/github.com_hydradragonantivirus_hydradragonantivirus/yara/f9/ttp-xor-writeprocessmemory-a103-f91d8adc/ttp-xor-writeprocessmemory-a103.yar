rule TTP_XOR_WriteProcessMemory_a103 {
  strings:
    $key_a103 = { f6 71 [2] c4 53 [2] c2 66 [2] ec 66 [2] d3 7a }

  condition:
    any of them
}