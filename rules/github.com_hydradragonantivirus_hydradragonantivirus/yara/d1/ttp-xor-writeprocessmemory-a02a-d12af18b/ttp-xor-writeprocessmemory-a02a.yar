rule TTP_XOR_WriteProcessMemory_a02a {
  strings:
    $key_a02a = { f7 58 [2] c5 7a [2] c3 4f [2] ed 4f [2] d2 53 }

  condition:
    any of them
}