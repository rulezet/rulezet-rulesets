rule TTP_XOR_WriteProcessMemory_771a {
  strings:
    $key_771a = { 20 68 [2] 12 4a [2] 14 7f [2] 3a 7f [2] 05 63 }

  condition:
    any of them
}