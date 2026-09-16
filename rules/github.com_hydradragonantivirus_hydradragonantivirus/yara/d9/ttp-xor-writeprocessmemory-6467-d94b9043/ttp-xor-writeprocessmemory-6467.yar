rule TTP_XOR_WriteProcessMemory_6467 {
  strings:
    $key_6467 = { 33 15 [2] 01 37 [2] 07 02 [2] 29 02 [2] 16 1e }

  condition:
    any of them
}