rule TTP_XOR_WriteProcessMemory_16a5 {
  strings:
    $key_16a5 = { 41 d7 [2] 73 f5 [2] 75 c0 [2] 5b c0 [2] 64 dc }

  condition:
    any of them
}