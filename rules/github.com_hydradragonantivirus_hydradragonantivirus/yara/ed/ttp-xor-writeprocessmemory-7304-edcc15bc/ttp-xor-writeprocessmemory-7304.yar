rule TTP_XOR_WriteProcessMemory_7304 {
  strings:
    $key_7304 = { 24 76 [2] 16 54 [2] 10 61 [2] 3e 61 [2] 01 7d }

  condition:
    any of them
}