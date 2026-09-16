rule TTP_XOR_WriteProcessMemory_0c8f {
  strings:
    $key_0c8f = { 5b fd [2] 69 df [2] 6f ea [2] 41 ea [2] 7e f6 }

  condition:
    any of them
}