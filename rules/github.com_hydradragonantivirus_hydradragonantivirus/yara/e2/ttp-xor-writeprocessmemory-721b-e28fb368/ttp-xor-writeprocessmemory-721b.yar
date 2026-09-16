rule TTP_XOR_WriteProcessMemory_721b {
  strings:
    $key_721b = { 25 69 [2] 17 4b [2] 11 7e [2] 3f 7e [2] 00 62 }

  condition:
    any of them
}