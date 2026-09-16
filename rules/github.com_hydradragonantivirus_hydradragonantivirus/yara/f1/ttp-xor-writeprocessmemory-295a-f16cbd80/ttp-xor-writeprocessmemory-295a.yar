rule TTP_XOR_WriteProcessMemory_295a {
  strings:
    $key_295a = { 7e 28 [2] 4c 0a [2] 4a 3f [2] 64 3f [2] 5b 23 }

  condition:
    any of them
}