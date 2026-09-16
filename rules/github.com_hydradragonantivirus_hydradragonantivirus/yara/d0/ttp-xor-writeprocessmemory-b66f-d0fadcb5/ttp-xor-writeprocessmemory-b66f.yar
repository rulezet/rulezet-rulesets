rule TTP_XOR_WriteProcessMemory_b66f {
  strings:
    $key_b66f = { e1 1d [2] d3 3f [2] d5 0a [2] fb 0a [2] c4 16 }

  condition:
    any of them
}