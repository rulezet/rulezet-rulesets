rule TTP_XOR_WriteProcessMemory_4d61 {
  strings:
    $key_4d61 = { 1a 13 [2] 28 31 [2] 2e 04 [2] 00 04 [2] 3f 18 }

  condition:
    any of them
}