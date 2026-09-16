rule TTP_XOR_WriteProcessMemory_a158 {
  strings:
    $key_a158 = { f6 2a [2] c4 08 [2] c2 3d [2] ec 3d [2] d3 21 }

  condition:
    any of them
}