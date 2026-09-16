rule TTP_XOR_WriteProcessMemory_c48f {
  strings:
    $key_c48f = { 93 fd [2] a1 df [2] a7 ea [2] 89 ea [2] b6 f6 }

  condition:
    any of them
}