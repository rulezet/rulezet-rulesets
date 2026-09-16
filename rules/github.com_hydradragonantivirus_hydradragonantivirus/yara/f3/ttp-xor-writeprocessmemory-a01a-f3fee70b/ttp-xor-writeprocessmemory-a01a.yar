rule TTP_XOR_WriteProcessMemory_a01a {
  strings:
    $key_a01a = { f7 68 [2] c5 4a [2] c3 7f [2] ed 7f [2] d2 63 }

  condition:
    any of them
}