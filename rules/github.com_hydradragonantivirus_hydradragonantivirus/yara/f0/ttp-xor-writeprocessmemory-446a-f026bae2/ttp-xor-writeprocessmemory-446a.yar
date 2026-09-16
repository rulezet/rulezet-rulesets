rule TTP_XOR_WriteProcessMemory_446a {
  strings:
    $key_446a = { 13 18 [2] 21 3a [2] 27 0f [2] 09 0f [2] 36 13 }

  condition:
    any of them
}