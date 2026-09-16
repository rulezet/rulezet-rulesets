rule TTP_XOR_WriteProcessMemory_7229 {
  strings:
    $key_7229 = { 25 5b [2] 17 79 [2] 11 4c [2] 3f 4c [2] 00 50 }

  condition:
    any of them
}