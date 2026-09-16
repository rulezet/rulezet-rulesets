rule TTP_XOR_WriteProcessMemory_e18c {
  strings:
    $key_e18c = { b6 fe [2] 84 dc [2] 82 e9 [2] ac e9 [2] 93 f5 }

  condition:
    any of them
}