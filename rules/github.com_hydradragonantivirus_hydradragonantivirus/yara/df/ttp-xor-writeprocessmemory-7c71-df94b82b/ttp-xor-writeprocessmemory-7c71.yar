rule TTP_XOR_WriteProcessMemory_7c71 {
  strings:
    $key_7c71 = { 2b 03 [2] 19 21 [2] 1f 14 [2] 31 14 [2] 0e 08 }

  condition:
    any of them
}