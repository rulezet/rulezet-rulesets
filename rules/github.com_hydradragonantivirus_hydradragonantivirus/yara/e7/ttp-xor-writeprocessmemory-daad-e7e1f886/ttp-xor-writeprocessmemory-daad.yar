rule TTP_XOR_WriteProcessMemory_daad {
  strings:
    $key_daad = { 8d df [2] bf fd [2] b9 c8 [2] 97 c8 [2] a8 d4 }

  condition:
    any of them
}