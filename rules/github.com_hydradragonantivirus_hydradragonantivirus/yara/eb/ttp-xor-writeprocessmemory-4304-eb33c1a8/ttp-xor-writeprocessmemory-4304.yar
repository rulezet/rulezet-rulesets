rule TTP_XOR_WriteProcessMemory_4304 {
  strings:
    $key_4304 = { 14 76 [2] 26 54 [2] 20 61 [2] 0e 61 [2] 31 7d }

  condition:
    any of them
}