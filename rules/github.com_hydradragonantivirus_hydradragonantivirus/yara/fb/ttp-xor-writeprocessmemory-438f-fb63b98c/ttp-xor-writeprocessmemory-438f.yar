rule TTP_XOR_WriteProcessMemory_438f {
  strings:
    $key_438f = { 14 fd [2] 26 df [2] 20 ea [2] 0e ea [2] 31 f6 }

  condition:
    any of them
}