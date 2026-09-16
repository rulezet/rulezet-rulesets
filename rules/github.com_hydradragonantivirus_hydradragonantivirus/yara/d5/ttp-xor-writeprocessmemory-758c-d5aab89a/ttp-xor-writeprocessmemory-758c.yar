rule TTP_XOR_WriteProcessMemory_758c {
  strings:
    $key_758c = { 22 fe [2] 10 dc [2] 16 e9 [2] 38 e9 [2] 07 f5 }

  condition:
    any of them
}