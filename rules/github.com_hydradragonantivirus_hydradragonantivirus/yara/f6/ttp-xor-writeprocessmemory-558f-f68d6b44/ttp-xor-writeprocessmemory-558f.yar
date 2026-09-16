rule TTP_XOR_WriteProcessMemory_558f {
  strings:
    $key_558f = { 02 fd [2] 30 df [2] 36 ea [2] 18 ea [2] 27 f6 }

  condition:
    any of them
}