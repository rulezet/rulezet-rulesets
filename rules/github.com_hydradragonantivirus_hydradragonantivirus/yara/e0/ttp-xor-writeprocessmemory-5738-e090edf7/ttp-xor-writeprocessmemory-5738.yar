rule TTP_XOR_WriteProcessMemory_5738 {
  strings:
    $key_5738 = { 00 4a [2] 32 68 [2] 34 5d [2] 1a 5d [2] 25 41 }

  condition:
    any of them
}