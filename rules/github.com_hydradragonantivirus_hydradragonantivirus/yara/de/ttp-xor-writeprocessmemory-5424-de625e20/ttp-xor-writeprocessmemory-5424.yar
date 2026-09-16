rule TTP_XOR_WriteProcessMemory_5424 {
  strings:
    $key_5424 = { 03 56 [2] 31 74 [2] 37 41 [2] 19 41 [2] 26 5d }

  condition:
    any of them
}