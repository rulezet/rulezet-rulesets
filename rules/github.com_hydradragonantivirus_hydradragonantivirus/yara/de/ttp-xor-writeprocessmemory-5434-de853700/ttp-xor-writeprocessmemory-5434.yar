rule TTP_XOR_WriteProcessMemory_5434 {
  strings:
    $key_5434 = { 03 46 [2] 31 64 [2] 37 51 [2] 19 51 [2] 26 4d }

  condition:
    any of them
}