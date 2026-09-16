rule TTP_XOR_WriteProcessMemory_5a61 {
  strings:
    $key_5a61 = { 0d 13 [2] 3f 31 [2] 39 04 [2] 17 04 [2] 28 18 }

  condition:
    any of them
}