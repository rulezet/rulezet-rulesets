rule TTP_XOR_WriteProcessMemory_b65a {
  strings:
    $key_b65a = { e1 28 [2] d3 0a [2] d5 3f [2] fb 3f [2] c4 23 }

  condition:
    any of them
}