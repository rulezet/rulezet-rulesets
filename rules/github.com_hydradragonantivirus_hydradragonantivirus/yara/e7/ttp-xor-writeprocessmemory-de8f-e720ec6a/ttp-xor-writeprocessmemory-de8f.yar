rule TTP_XOR_WriteProcessMemory_de8f {
  strings:
    $key_de8f = { 89 fd [2] bb df [2] bd ea [2] 93 ea [2] ac f6 }

  condition:
    any of them
}