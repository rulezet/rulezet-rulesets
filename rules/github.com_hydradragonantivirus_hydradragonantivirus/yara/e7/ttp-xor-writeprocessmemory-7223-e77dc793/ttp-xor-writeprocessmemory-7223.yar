rule TTP_XOR_WriteProcessMemory_7223 {
  strings:
    $key_7223 = { 25 51 [2] 17 73 [2] 11 46 [2] 3f 46 [2] 00 5a }

  condition:
    any of them
}