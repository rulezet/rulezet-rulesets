rule TTP_XOR_WriteProcessMemory_272a {
  strings:
    $key_272a = { 70 58 [2] 42 7a [2] 44 4f [2] 6a 4f [2] 55 53 }

  condition:
    any of them
}