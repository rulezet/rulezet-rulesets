rule TTP_XOR_WriteProcessMemory_b66a {
  strings:
    $key_b66a = { e1 18 [2] d3 3a [2] d5 0f [2] fb 0f [2] c4 13 }

  condition:
    any of them
}