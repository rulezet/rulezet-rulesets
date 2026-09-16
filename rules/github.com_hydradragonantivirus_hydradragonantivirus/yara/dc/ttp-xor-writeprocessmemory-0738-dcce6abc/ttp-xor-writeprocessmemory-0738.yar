rule TTP_XOR_WriteProcessMemory_0738 {
  strings:
    $key_0738 = { 50 4a [2] 62 68 [2] 64 5d [2] 4a 5d [2] 75 41 }

  condition:
    any of them
}