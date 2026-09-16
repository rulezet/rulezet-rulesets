rule TTP_XOR_WriteProcessMemory_7269 {
  strings:
    $key_7269 = { 25 1b [2] 17 39 [2] 11 0c [2] 3f 0c [2] 00 10 }

  condition:
    any of them
}