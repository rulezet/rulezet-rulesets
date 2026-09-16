rule TTP_XOR_WriteProcessMemory_b07f {
  strings:
    $key_b07f = { e7 0d [2] d5 2f [2] d3 1a [2] fd 1a [2] c2 06 }

  condition:
    any of them
}