rule TTP_XOR_WriteProcessMemory_f53a {
  strings:
    $key_f53a = { a2 48 [2] 90 6a [2] 96 5f [2] b8 5f [2] 87 43 }

  condition:
    any of them
}