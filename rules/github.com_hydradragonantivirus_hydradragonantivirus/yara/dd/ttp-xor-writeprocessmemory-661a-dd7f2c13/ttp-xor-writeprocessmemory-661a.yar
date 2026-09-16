rule TTP_XOR_WriteProcessMemory_661a {
  strings:
    $key_661a = { 31 68 [2] 03 4a [2] 05 7f [2] 2b 7f [2] 14 63 }

  condition:
    any of them
}