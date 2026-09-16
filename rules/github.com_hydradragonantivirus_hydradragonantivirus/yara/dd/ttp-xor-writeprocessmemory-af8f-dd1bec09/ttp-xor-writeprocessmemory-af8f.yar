rule TTP_XOR_WriteProcessMemory_af8f {
  strings:
    $key_af8f = { f8 fd [2] ca df [2] cc ea [2] e2 ea [2] dd f6 }

  condition:
    any of them
}