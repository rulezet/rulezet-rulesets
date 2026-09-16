rule TTP_XOR_WriteProcessMemory_022a {
  strings:
    $key_022a = { 55 58 [2] 67 7a [2] 61 4f [2] 4f 4f [2] 70 53 }

  condition:
    any of them
}