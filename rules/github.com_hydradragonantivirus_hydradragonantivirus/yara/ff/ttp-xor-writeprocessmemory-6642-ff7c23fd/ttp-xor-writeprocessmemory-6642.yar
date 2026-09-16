rule TTP_XOR_WriteProcessMemory_6642 {
  strings:
    $key_6642 = { 31 30 [2] 03 12 [2] 05 27 [2] 2b 27 [2] 14 3b }

  condition:
    any of them
}