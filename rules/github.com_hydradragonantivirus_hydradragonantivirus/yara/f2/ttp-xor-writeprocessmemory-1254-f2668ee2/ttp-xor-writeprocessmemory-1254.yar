rule TTP_XOR_WriteProcessMemory_1254 {
  strings:
    $key_1254 = { 45 26 [2] 77 04 [2] 71 31 [2] 5f 31 [2] 60 2d }

  condition:
    any of them
}