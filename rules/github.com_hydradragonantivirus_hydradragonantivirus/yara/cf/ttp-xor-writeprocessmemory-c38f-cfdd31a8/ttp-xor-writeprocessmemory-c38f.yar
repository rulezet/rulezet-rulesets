rule TTP_XOR_WriteProcessMemory_c38f {
  strings:
    $key_c38f = { 94 fd [2] a6 df [2] a0 ea [2] 8e ea [2] b1 f6 }

  condition:
    any of them
}