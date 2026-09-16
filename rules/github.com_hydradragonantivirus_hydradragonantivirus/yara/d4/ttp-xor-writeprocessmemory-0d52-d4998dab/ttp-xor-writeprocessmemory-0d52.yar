rule TTP_XOR_WriteProcessMemory_0d52 {
  strings:
    $key_0d52 = { 5a 20 [2] 68 02 [2] 6e 37 [2] 40 37 [2] 7f 2b }

  condition:
    any of them
}