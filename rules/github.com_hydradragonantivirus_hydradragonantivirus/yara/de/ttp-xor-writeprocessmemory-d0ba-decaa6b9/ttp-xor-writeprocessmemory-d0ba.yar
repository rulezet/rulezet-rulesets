rule TTP_XOR_WriteProcessMemory_d0ba {
  strings:
    $key_d0ba = { 87 c8 [2] b5 ea [2] b3 df [2] 9d df [2] a2 c3 }

  condition:
    any of them
}