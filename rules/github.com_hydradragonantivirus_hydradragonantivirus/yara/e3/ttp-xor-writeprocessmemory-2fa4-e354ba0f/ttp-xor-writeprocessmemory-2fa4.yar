rule TTP_XOR_WriteProcessMemory_2fa4 {
  strings:
    $key_2fa4 = { 78 d6 [2] 4a f4 [2] 4c c1 [2] 62 c1 [2] 5d dd }

  condition:
    any of them
}