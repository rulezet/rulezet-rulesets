rule TTP_XOR_WriteProcessMemory_133a {
  strings:
    $key_133a = { 44 48 [2] 76 6a [2] 70 5f [2] 5e 5f [2] 61 43 }

  condition:
    any of them
}