rule TTP_XOR_WriteProcessMemory_7c7a {
  strings:
    $key_7c7a = { 2b 08 [2] 19 2a [2] 1f 1f [2] 31 1f [2] 0e 03 }

  condition:
    any of them
}