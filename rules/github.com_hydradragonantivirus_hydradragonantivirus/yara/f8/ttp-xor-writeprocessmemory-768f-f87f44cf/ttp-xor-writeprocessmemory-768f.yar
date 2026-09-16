rule TTP_XOR_WriteProcessMemory_768f {
  strings:
    $key_768f = { 21 fd [2] 13 df [2] 15 ea [2] 3b ea [2] 04 f6 }

  condition:
    any of them
}