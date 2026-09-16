rule TTP_XOR_WriteProcessMemory_7541 {
  strings:
    $key_7541 = { 22 33 [2] 10 11 [2] 16 24 [2] 38 24 [2] 07 38 }

  condition:
    any of them
}