rule TTP_XOR_WriteProcessMemory_fdba {
  strings:
    $key_fdba = { aa c8 [2] 98 ea [2] 9e df [2] b0 df [2] 8f c3 }

  condition:
    any of them
}