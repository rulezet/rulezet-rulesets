rule TTP_XOR_WriteProcessMemory_297c {
  strings:
    $key_297c = { 7e 0e [2] 4c 2c [2] 4a 19 [2] 64 19 [2] 5b 05 }

  condition:
    any of them
}