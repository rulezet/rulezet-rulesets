rule TTP_XOR_WriteProcessMemory_da8f {
  strings:
    $key_da8f = { 8d fd [2] bf df [2] b9 ea [2] 97 ea [2] a8 f6 }

  condition:
    any of them
}