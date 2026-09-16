rule TTP_XOR_WriteProcessMemory_0d67 {
  strings:
    $key_0d67 = { 5a 15 [2] 68 37 [2] 6e 02 [2] 40 02 [2] 7f 1e }

  condition:
    any of them
}