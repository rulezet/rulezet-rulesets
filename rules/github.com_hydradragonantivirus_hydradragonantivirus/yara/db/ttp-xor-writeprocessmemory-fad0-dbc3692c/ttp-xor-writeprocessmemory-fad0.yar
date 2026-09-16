rule TTP_XOR_WriteProcessMemory_fad0 {
  strings:
    $key_fad0 = { ad a2 [2] 9f 80 [2] 99 b5 [2] b7 b5 [2] 88 a9 }

  condition:
    any of them
}