rule TTP_XOR_WriteProcessMemory_6621 {
  strings:
    $key_6621 = { 31 53 [2] 03 71 [2] 05 44 [2] 2b 44 [2] 14 58 }

  condition:
    any of them
}