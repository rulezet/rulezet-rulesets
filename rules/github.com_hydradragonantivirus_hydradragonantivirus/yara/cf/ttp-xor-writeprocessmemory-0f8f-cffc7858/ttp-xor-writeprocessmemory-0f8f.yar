rule TTP_XOR_WriteProcessMemory_0f8f {
  strings:
    $key_0f8f = { 58 fd [2] 6a df [2] 6c ea [2] 42 ea [2] 7d f6 }

  condition:
    any of them
}