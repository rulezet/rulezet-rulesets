rule TTP_XOR_WriteProcessMemory_631a {
  strings:
    $key_631a = { 34 68 [2] 06 4a [2] 00 7f [2] 2e 7f [2] 11 63 }

  condition:
    any of them
}