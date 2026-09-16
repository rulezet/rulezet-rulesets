rule TTP_XOR_WriteProcessMemory_6d7c {
  strings:
    $key_6d7c = { 3a 0e [2] 08 2c [2] 0e 19 [2] 20 19 [2] 1f 05 }

  condition:
    any of them
}