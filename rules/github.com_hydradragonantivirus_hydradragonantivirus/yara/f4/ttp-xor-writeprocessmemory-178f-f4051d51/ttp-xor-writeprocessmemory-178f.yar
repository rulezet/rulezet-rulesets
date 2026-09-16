rule TTP_XOR_WriteProcessMemory_178f {
  strings:
    $key_178f = { 40 fd [2] 72 df [2] 74 ea [2] 5a ea [2] 65 f6 }

  condition:
    any of them
}