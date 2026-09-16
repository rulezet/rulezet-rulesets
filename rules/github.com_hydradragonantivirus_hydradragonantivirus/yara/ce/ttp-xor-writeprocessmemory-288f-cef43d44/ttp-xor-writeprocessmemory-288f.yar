rule TTP_XOR_WriteProcessMemory_288f {
  strings:
    $key_288f = { 7f fd [2] 4d df [2] 4b ea [2] 65 ea [2] 5a f6 }

  condition:
    any of them
}