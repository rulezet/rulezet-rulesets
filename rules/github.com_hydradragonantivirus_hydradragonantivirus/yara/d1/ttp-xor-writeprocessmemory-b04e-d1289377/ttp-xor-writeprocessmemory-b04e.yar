rule TTP_XOR_WriteProcessMemory_b04e {
  strings:
    $key_b04e = { e7 3c [2] d5 1e [2] d3 2b [2] fd 2b [2] c2 37 }

  condition:
    any of them
}