rule TTP_XOR_WriteProcessMemory_b060 {
  strings:
    $key_b060 = { e7 12 [2] d5 30 [2] d3 05 [2] fd 05 [2] c2 19 }

  condition:
    any of them
}