rule TTP_XOR_WriteProcessMemory_fa5c {
  strings:
    $key_fa5c = { ad 2e [2] 9f 0c [2] 99 39 [2] b7 39 [2] 88 25 }

  condition:
    any of them
}