rule TTP_XOR_WriteProcessMemory_0aa7 {
  strings:
    $key_0aa7 = { 5d d5 [2] 6f f7 [2] 69 c2 [2] 47 c2 [2] 78 de }

  condition:
    any of them
}