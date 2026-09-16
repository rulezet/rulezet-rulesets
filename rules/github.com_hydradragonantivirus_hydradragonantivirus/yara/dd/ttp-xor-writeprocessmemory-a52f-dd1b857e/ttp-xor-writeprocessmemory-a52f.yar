rule TTP_XOR_WriteProcessMemory_a52f {
  strings:
    $key_a52f = { f2 5d [2] c0 7f [2] c6 4a [2] e8 4a [2] d7 56 }

  condition:
    any of them
}