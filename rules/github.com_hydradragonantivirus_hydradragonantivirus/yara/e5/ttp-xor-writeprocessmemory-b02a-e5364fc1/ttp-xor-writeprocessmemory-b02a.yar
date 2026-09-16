rule TTP_XOR_WriteProcessMemory_b02a {
  strings:
    $key_b02a = { e7 58 [2] d5 7a [2] d3 4f [2] fd 4f [2] c2 53 }

  condition:
    any of them
}