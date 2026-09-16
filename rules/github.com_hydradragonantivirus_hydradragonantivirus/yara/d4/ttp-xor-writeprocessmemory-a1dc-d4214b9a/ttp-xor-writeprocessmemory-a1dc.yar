rule TTP_XOR_WriteProcessMemory_a1dc {
  strings:
    $key_a1dc = { f6 ae [2] c4 8c [2] c2 b9 [2] ec b9 [2] d3 a5 }

  condition:
    any of them
}