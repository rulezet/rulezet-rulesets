rule TTP_XOR_WriteProcessMemory_a50a {
  strings:
    $key_a50a = { f2 78 [2] c0 5a [2] c6 6f [2] e8 6f [2] d7 73 }

  condition:
    any of them
}