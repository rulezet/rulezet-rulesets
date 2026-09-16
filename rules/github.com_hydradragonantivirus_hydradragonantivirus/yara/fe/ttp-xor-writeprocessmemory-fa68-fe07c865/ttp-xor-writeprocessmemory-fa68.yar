rule TTP_XOR_WriteProcessMemory_fa68 {
  strings:
    $key_fa68 = { ad 1a [2] 9f 38 [2] 99 0d [2] b7 0d [2] 88 11 }

  condition:
    any of them
}