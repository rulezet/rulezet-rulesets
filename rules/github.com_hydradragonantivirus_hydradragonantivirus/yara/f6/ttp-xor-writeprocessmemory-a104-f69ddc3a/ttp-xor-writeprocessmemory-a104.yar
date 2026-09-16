rule TTP_XOR_WriteProcessMemory_a104 {
  strings:
    $key_a104 = { f6 76 [2] c4 54 [2] c2 61 [2] ec 61 [2] d3 7d }

  condition:
    any of them
}