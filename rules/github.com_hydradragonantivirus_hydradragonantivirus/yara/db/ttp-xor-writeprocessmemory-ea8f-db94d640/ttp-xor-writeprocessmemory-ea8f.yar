rule TTP_XOR_WriteProcessMemory_ea8f {
  strings:
    $key_ea8f = { bd fd [2] 8f df [2] 89 ea [2] a7 ea [2] 98 f6 }

  condition:
    any of them
}