rule TTP_XOR_WriteProcessMemory_c08f {
  strings:
    $key_c08f = { 97 fd [2] a5 df [2] a3 ea [2] 8d ea [2] b2 f6 }

  condition:
    any of them
}