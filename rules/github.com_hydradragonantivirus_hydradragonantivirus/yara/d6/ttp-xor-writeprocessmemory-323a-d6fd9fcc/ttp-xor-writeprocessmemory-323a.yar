rule TTP_XOR_WriteProcessMemory_323a {
  strings:
    $key_323a = { 65 48 [2] 57 6a [2] 51 5f [2] 7f 5f [2] 40 43 }

  condition:
    any of them
}