rule TTP_XOR_WriteProcessMemory_6c7c {
  strings:
    $key_6c7c = { 3b 0e [2] 09 2c [2] 0f 19 [2] 21 19 [2] 1e 05 }

  condition:
    any of them
}