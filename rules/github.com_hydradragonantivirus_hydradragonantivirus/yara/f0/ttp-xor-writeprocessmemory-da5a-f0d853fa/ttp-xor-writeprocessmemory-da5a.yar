rule TTP_XOR_WriteProcessMemory_da5a {
  strings:
    $key_da5a = { 8d 28 [2] bf 0a [2] b9 3f [2] 97 3f [2] a8 23 }

  condition:
    any of them
}