rule TTP_XOR_WriteProcessMemory_0d43 {
  strings:
    $key_0d43 = { 5a 31 [2] 68 13 [2] 6e 26 [2] 40 26 [2] 7f 3a }

  condition:
    any of them
}