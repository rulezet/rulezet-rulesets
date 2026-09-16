rule TTP_XOR_WriteProcessMemory_087c {
  strings:
    $key_087c = { 5f 0e [2] 6d 2c [2] 6b 19 [2] 45 19 [2] 7a 05 }

  condition:
    any of them
}