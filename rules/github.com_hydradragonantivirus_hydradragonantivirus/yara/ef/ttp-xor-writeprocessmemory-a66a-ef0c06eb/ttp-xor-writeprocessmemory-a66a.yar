rule TTP_XOR_WriteProcessMemory_a66a {
  strings:
    $key_a66a = { f1 18 [2] c3 3a [2] c5 0f [2] eb 0f [2] d4 13 }

  condition:
    any of them
}