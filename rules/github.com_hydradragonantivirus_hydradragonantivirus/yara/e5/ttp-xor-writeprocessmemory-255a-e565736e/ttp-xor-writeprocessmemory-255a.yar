rule TTP_XOR_WriteProcessMemory_255a {
  strings:
    $key_255a = { 72 28 [2] 40 0a [2] 46 3f [2] 68 3f [2] 57 23 }

  condition:
    any of them
}