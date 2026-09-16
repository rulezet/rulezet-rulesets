rule TTP_XOR_WriteProcessMemory_4d8f {
  strings:
    $key_4d8f = { 1a fd [2] 28 df [2] 2e ea [2] 00 ea [2] 3f f6 }

  condition:
    any of them
}