rule TTP_XOR_WriteProcessMemory_a4e8 {
  strings:
    $key_a4e8 = { f3 9a [2] c1 b8 [2] c7 8d [2] e9 8d [2] d6 91 }

  condition:
    any of them
}