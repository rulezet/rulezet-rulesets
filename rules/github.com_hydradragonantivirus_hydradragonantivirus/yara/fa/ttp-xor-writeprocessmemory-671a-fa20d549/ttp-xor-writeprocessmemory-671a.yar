rule TTP_XOR_WriteProcessMemory_671a {
  strings:
    $key_671a = { 30 68 [2] 02 4a [2] 04 7f [2] 2a 7f [2] 15 63 }

  condition:
    any of them
}