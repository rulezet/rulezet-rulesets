rule TTP_XOR_WriteProcessMemory_a50d {
  strings:
    $key_a50d = { f2 7f [2] c0 5d [2] c6 68 [2] e8 68 [2] d7 74 }

  condition:
    any of them
}