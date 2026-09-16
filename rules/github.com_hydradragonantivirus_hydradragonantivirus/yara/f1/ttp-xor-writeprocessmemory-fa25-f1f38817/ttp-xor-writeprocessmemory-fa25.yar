rule TTP_XOR_WriteProcessMemory_fa25 {
  strings:
    $key_fa25 = { ad 57 [2] 9f 75 [2] 99 40 [2] b7 40 [2] 88 5c }

  condition:
    any of them
}