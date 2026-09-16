rule TTP_XOR_WriteProcessMemory_4b4a {
  strings:
    $key_4b4a = { 1c 38 [2] 2e 1a [2] 28 2f [2] 06 2f [2] 39 33 }

  condition:
    any of them
}