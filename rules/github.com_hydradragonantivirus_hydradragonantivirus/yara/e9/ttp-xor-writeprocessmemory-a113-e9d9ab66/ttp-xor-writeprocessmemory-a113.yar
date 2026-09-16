rule TTP_XOR_WriteProcessMemory_a113 {
  strings:
    $key_a113 = { f6 61 [2] c4 43 [2] c2 76 [2] ec 76 [2] d3 6a }

  condition:
    any of them
}