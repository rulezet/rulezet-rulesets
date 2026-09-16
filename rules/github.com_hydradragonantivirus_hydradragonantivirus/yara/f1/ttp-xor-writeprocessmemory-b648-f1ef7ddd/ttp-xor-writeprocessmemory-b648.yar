rule TTP_XOR_WriteProcessMemory_b648 {
  strings:
    $key_b648 = { e1 3a [2] d3 18 [2] d5 2d [2] fb 2d [2] c4 31 }

  condition:
    any of them
}