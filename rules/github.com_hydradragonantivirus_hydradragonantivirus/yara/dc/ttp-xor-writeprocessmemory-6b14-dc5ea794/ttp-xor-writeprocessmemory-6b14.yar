rule TTP_XOR_WriteProcessMemory_6b14 {
  strings:
    $key_6b14 = { 3c 66 [2] 0e 44 [2] 08 71 [2] 26 71 [2] 19 6d }

  condition:
    any of them
}