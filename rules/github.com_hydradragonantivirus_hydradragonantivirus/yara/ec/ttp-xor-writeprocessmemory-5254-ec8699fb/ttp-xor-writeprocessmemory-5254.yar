rule TTP_XOR_WriteProcessMemory_5254 {
  strings:
    $key_5254 = { 05 26 [2] 37 04 [2] 31 31 [2] 1f 31 [2] 20 2d }

  condition:
    any of them
}