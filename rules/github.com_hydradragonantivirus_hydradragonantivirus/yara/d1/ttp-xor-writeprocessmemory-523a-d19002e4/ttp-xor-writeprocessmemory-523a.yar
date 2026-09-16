rule TTP_XOR_WriteProcessMemory_523a {
  strings:
    $key_523a = { 05 48 [2] 37 6a [2] 31 5f [2] 1f 5f [2] 20 43 }

  condition:
    any of them
}