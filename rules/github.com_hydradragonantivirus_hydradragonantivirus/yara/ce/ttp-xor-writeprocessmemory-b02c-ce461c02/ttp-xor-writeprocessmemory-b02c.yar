rule TTP_XOR_WriteProcessMemory_b02c {
  strings:
    $key_b02c = { e7 5e [2] d5 7c [2] d3 49 [2] fd 49 [2] c2 55 }

  condition:
    any of them
}