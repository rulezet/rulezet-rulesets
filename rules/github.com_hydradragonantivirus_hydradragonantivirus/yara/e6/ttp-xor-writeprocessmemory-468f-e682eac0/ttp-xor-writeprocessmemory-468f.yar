rule TTP_XOR_WriteProcessMemory_468f {
  strings:
    $key_468f = { 11 fd [2] 23 df [2] 25 ea [2] 0b ea [2] 34 f6 }

  condition:
    any of them
}