rule TTP_XOR_WriteProcessMemory_a569 {
  strings:
    $key_a569 = { f2 1b [2] c0 39 [2] c6 0c [2] e8 0c [2] d7 10 }

  condition:
    any of them
}