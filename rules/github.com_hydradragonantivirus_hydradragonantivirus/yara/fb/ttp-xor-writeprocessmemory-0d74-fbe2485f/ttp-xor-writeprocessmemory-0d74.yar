rule TTP_XOR_WriteProcessMemory_0d74 {
  strings:
    $key_0d74 = { 5a 06 [2] 68 24 [2] 6e 11 [2] 40 11 [2] 7f 0d }

  condition:
    any of them
}