rule TTP_XOR_WriteProcessMemory_a721 {
  strings:
    $key_a721 = { f0 53 [2] c2 71 [2] c4 44 [2] ea 44 [2] d5 58 }

  condition:
    any of them
}