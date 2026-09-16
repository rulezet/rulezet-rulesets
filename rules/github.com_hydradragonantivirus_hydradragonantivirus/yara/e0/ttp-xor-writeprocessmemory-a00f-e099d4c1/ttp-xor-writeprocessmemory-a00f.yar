rule TTP_XOR_WriteProcessMemory_a00f {
  strings:
    $key_a00f = { f7 7d [2] c5 5f [2] c3 6a [2] ed 6a [2] d2 76 }

  condition:
    any of them
}