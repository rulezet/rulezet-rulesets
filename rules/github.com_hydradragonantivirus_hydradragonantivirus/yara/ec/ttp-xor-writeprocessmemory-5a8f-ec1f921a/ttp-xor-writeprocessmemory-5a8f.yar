rule TTP_XOR_WriteProcessMemory_5a8f {
  strings:
    $key_5a8f = { 0d fd [2] 3f df [2] 39 ea [2] 17 ea [2] 28 f6 }

  condition:
    any of them
}