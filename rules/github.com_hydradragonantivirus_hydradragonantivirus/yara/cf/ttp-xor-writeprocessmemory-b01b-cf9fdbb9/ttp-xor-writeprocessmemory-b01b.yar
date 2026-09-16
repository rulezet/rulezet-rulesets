rule TTP_XOR_WriteProcessMemory_b01b {
  strings:
    $key_b01b = { e7 69 [2] d5 4b [2] d3 7e [2] fd 7e [2] c2 62 }

  condition:
    any of them
}