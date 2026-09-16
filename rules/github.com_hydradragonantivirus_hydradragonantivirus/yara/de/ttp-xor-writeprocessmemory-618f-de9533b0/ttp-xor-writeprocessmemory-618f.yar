rule TTP_XOR_WriteProcessMemory_618f {
  strings:
    $key_618f = { 36 fd [2] 04 df [2] 02 ea [2] 2c ea [2] 13 f6 }

  condition:
    any of them
}