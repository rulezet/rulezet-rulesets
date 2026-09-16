rule TTP_XOR_WriteProcessMemory_2fa1 {
  strings:
    $key_2fa1 = { 78 d3 [2] 4a f1 [2] 4c c4 [2] 62 c4 [2] 5d d8 }

  condition:
    any of them
}