rule TTP_XOR_WriteProcessMemory_a575 {
  strings:
    $key_a575 = { f2 07 [2] c0 25 [2] c6 10 [2] e8 10 [2] d7 0c }

  condition:
    any of them
}