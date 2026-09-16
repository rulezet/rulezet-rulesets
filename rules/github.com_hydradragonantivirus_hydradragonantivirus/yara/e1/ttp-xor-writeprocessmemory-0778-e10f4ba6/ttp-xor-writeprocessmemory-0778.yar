rule TTP_XOR_WriteProcessMemory_0778 {
  strings:
    $key_0778 = { 50 0a [2] 62 28 [2] 64 1d [2] 4a 1d [2] 75 01 }

  condition:
    any of them
}