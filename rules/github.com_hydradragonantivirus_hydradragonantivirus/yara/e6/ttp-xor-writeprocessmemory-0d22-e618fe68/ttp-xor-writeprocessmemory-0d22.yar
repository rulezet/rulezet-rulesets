rule TTP_XOR_WriteProcessMemory_0d22 {
  strings:
    $key_0d22 = { 5a 50 [2] 68 72 [2] 6e 47 [2] 40 47 [2] 7f 5b }

  condition:
    any of them
}