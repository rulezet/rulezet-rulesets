rule TTP_XOR_WriteProcessMemory_a239 {
  strings:
    $key_a239 = { f5 4b [2] c7 69 [2] c1 5c [2] ef 5c [2] d0 40 }

  condition:
    any of them
}