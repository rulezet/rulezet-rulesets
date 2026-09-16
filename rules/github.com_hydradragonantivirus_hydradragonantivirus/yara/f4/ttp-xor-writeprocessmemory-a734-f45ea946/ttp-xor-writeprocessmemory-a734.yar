rule TTP_XOR_WriteProcessMemory_a734 {
  strings:
    $key_a734 = { f0 46 [2] c2 64 [2] c4 51 [2] ea 51 [2] d5 4d }

  condition:
    any of them
}