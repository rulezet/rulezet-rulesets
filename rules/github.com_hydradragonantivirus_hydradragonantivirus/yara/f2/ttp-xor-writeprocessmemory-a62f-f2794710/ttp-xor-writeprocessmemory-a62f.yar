rule TTP_XOR_WriteProcessMemory_a62f {
  strings:
    $key_a62f = { f1 5d [2] c3 7f [2] c5 4a [2] eb 4a [2] d4 56 }

  condition:
    any of them
}