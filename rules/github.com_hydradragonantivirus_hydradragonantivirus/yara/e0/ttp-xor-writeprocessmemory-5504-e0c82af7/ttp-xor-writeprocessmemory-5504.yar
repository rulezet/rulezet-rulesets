rule TTP_XOR_WriteProcessMemory_5504 {
  strings:
    $key_5504 = { 02 76 [2] 30 54 [2] 36 61 [2] 18 61 [2] 27 7d }

  condition:
    any of them
}