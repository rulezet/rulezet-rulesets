rule TTP_XOR_WriteProcessMemory_fa60 {
  strings:
    $key_fa60 = { ad 12 [2] 9f 30 [2] 99 05 [2] b7 05 [2] 88 19 }

  condition:
    any of them
}