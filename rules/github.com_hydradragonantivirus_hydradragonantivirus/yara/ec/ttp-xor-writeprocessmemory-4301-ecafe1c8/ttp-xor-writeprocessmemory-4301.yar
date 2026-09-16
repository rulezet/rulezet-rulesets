rule TTP_XOR_WriteProcessMemory_4301 {
  strings:
    $key_4301 = { 14 73 [2] 26 51 [2] 20 64 [2] 0e 64 [2] 31 78 }

  condition:
    any of them
}