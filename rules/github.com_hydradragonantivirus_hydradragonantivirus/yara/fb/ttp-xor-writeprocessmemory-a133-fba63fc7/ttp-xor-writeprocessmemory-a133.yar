rule TTP_XOR_WriteProcessMemory_a133 {
  strings:
    $key_a133 = { f6 41 [2] c4 63 [2] c2 56 [2] ec 56 [2] d3 4a }

  condition:
    any of them
}