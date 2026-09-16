rule TTP_XOR_WriteProcessMemory_2fa5 {
  strings:
    $key_2fa5 = { 78 d7 [2] 4a f5 [2] 4c c0 [2] 62 c0 [2] 5d dc }

  condition:
    any of them
}