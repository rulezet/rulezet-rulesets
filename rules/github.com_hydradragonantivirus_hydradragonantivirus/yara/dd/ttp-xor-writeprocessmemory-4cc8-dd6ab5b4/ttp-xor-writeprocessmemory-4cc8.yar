rule TTP_XOR_WriteProcessMemory_4cc8 {
  strings:
    $key_4cc8 = { 1b ba [2] 29 98 [2] 2f ad [2] 01 ad [2] 3e b1 }

  condition:
    any of them
}