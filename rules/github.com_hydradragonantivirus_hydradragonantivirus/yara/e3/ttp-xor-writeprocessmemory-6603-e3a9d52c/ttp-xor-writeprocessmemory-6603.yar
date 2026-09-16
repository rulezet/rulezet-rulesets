rule TTP_XOR_WriteProcessMemory_6603 {
  strings:
    $key_6603 = { 31 71 [2] 03 53 [2] 05 66 [2] 2b 66 [2] 14 7a }

  condition:
    any of them
}