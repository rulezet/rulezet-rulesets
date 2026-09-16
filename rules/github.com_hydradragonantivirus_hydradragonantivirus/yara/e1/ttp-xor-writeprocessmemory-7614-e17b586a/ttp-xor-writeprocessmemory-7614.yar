rule TTP_XOR_WriteProcessMemory_7614 {
  strings:
    $key_7614 = { 21 66 [2] 13 44 [2] 15 71 [2] 3b 71 [2] 04 6d }

  condition:
    any of them
}