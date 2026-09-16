rule TTP_XOR_WriteProcessMemory_231a {
  strings:
    $key_231a = { 74 68 [2] 46 4a [2] 40 7f [2] 6e 7f [2] 51 63 }

  condition:
    any of them
}