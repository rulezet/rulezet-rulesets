rule TTP_XOR_WriteProcessMemory_d18f {
  strings:
    $key_d18f = { 86 fd [2] b4 df [2] b2 ea [2] 9c ea [2] a3 f6 }

  condition:
    any of them
}