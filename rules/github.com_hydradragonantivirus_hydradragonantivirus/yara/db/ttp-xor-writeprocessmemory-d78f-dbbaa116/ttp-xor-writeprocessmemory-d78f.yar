rule TTP_XOR_WriteProcessMemory_d78f {
  strings:
    $key_d78f = { 80 fd [2] b2 df [2] b4 ea [2] 9a ea [2] a5 f6 }

  condition:
    any of them
}