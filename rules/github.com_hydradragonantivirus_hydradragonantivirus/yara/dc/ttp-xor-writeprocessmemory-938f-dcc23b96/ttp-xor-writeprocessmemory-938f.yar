rule TTP_XOR_WriteProcessMemory_938f {
  strings:
    $key_938f = { c4 fd [2] f6 df [2] f0 ea [2] de ea [2] e1 f6 }

  condition:
    any of them
}