rule TTP_XOR_WriteProcessMemory_fa79 {
  strings:
    $key_fa79 = { ad 0b [2] 9f 29 [2] 99 1c [2] b7 1c [2] 88 00 }

  condition:
    any of them
}