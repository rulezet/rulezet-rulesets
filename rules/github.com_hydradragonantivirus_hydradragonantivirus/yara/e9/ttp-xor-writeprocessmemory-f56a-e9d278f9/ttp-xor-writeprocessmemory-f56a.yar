rule TTP_XOR_WriteProcessMemory_f56a {
  strings:
    $key_f56a = { a2 18 [2] 90 3a [2] 96 0f [2] b8 0f [2] 87 13 }

  condition:
    any of them
}