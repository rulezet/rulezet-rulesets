rule TTP_XOR_WriteProcessMemory_fa4a {
  strings:
    $key_fa4a = { ad 38 [2] 9f 1a [2] 99 2f [2] b7 2f [2] 88 33 }

  condition:
    any of them
}