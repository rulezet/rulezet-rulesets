rule TTP_XOR_WriteProcessMemory_b0ea {
  strings:
    $key_b0ea = { e7 98 [2] d5 ba [2] d3 8f [2] fd 8f [2] c2 93 }

  condition:
    any of them
}