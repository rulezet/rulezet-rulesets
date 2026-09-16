rule TTP_XOR_WriteProcessMemory_57fa {
  strings:
    $key_57fa = { 00 88 [2] 32 aa [2] 34 9f [2] 1a 9f [2] 25 83 }

  condition:
    any of them
}