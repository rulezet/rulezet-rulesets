rule TTP_XOR_WriteProcessMemory_195a {
  strings:
    $key_195a = { 4e 28 [2] 7c 0a [2] 7a 3f [2] 54 3f [2] 6b 23 }

  condition:
    any of them
}