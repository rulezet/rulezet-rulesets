rule TTP_XOR_WriteProcessMemory_471a {
  strings:
    $key_471a = { 10 68 [2] 22 4a [2] 24 7f [2] 0a 7f [2] 35 63 }

  condition:
    any of them
}