rule TTP_XOR_WriteProcessMemory_4164 {
  strings:
    $key_4164 = { 16 16 [2] 24 34 [2] 22 01 [2] 0c 01 [2] 33 1d }

  condition:
    any of them
}