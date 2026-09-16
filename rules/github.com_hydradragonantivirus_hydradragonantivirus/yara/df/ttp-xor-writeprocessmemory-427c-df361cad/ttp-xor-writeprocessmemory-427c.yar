rule TTP_XOR_WriteProcessMemory_427c {
  strings:
    $key_427c = { 15 0e [2] 27 2c [2] 21 19 [2] 0f 19 [2] 30 05 }

  condition:
    any of them
}