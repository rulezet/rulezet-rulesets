rule TTP_XOR_WriteProcessMemory_2fa0 {
  strings:
    $key_2fa0 = { 78 d2 [2] 4a f0 [2] 4c c5 [2] 62 c5 [2] 5d d9 }

  condition:
    any of them
}