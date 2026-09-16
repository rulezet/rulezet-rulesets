rule TTP_XOR_WriteProcessMemory_128f {
  strings:
    $key_128f = { 45 fd [2] 77 df [2] 71 ea [2] 5f ea [2] 60 f6 }

  condition:
    any of them
}