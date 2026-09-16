rule TTP_XOR_WriteProcessMemory_751a {
  strings:
    $key_751a = { 22 68 [2] 10 4a [2] 16 7f [2] 38 7f [2] 07 63 }

  condition:
    any of them
}