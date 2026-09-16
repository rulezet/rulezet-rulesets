rule TTP_XOR_WriteProcessMemory_616a {
  strings:
    $key_616a = { 36 18 [2] 04 3a [2] 02 0f [2] 2c 0f [2] 13 13 }

  condition:
    any of them
}