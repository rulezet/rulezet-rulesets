rule TTP_XOR_WriteProcessMemory_038f {
  strings:
    $key_038f = { 54 fd [2] 66 df [2] 60 ea [2] 4e ea [2] 71 f6 }

  condition:
    any of them
}