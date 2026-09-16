rule TTP_XOR_WriteProcessMemory_347a {
  strings:
    $key_347a = { 63 08 [2] 51 2a [2] 57 1f [2] 79 1f [2] 46 03 }

  condition:
    any of them
}