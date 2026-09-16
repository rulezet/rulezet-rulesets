rule TTP_XOR_WriteProcessMemory_628c {
  strings:
    $key_628c = { 35 fe [2] 07 dc [2] 01 e9 [2] 2f e9 [2] 10 f5 }

  condition:
    any of them
}