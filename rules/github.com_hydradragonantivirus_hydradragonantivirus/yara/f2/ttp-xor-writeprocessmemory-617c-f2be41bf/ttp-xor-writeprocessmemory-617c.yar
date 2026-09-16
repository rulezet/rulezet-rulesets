rule TTP_XOR_WriteProcessMemory_617c {
  strings:
    $key_617c = { 36 0e [2] 04 2c [2] 02 19 [2] 2c 19 [2] 13 05 }

  condition:
    any of them
}