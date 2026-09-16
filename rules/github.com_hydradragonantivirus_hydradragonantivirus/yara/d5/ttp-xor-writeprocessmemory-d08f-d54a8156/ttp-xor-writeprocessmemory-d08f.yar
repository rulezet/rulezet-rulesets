rule TTP_XOR_WriteProcessMemory_d08f {
  strings:
    $key_d08f = { 87 fd [2] b5 df [2] b3 ea [2] 9d ea [2] a2 f6 }

  condition:
    any of them
}