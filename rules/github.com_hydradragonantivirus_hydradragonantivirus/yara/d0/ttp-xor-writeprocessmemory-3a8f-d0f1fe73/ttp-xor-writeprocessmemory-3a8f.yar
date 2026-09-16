rule TTP_XOR_WriteProcessMemory_3a8f {
  strings:
    $key_3a8f = { 6d fd [2] 5f df [2] 59 ea [2] 77 ea [2] 48 f6 }

  condition:
    any of them
}