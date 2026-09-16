rule TTP_XOR_WriteProcessMemory_fa52 {
  strings:
    $key_fa52 = { ad 20 [2] 9f 02 [2] 99 37 [2] b7 37 [2] 88 2b }

  condition:
    any of them
}