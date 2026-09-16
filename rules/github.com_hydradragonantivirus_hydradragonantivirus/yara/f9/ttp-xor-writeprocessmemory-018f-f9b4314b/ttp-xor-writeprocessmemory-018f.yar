rule TTP_XOR_WriteProcessMemory_018f {
  strings:
    $key_018f = { 56 fd [2] 64 df [2] 62 ea [2] 4c ea [2] 73 f6 }

  condition:
    any of them
}