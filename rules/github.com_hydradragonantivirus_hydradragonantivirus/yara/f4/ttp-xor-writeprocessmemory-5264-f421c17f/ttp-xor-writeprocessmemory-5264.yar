rule TTP_XOR_WriteProcessMemory_5264 {
  strings:
    $key_5264 = { 05 16 [2] 37 34 [2] 31 01 [2] 1f 01 [2] 20 1d }

  condition:
    any of them
}