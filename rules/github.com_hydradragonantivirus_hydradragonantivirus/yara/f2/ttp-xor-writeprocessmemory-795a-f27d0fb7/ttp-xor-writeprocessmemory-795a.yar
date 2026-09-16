rule TTP_XOR_WriteProcessMemory_795a {
  strings:
    $key_795a = { 2e 28 [2] 1c 0a [2] 1a 3f [2] 34 3f [2] 0b 23 }

  condition:
    any of them
}