rule TTP_XOR_WriteProcessMemory_3164 {
  strings:
    $key_3164 = { 66 16 [2] 54 34 [2] 52 01 [2] 7c 01 [2] 43 1d }

  condition:
    any of them
}