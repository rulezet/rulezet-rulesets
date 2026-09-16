rule TTP_XOR_WriteProcessMemory_da3a {
  strings:
    $key_da3a = { 8d 48 [2] bf 6a [2] b9 5f [2] 97 5f [2] a8 43 }

  condition:
    any of them
}