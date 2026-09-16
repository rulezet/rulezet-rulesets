rule TTP_XOR_WriteProcessMemory_a203 {
  strings:
    $key_a203 = { f5 71 [2] c7 53 [2] c1 66 [2] ef 66 [2] d0 7a }

  condition:
    any of them
}