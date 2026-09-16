rule TTP_XOR_WriteProcessMemory_dd8c {
  strings:
    $key_dd8c = { 8a fe [2] b8 dc [2] be e9 [2] 90 e9 [2] af f5 }

  condition:
    any of them
}