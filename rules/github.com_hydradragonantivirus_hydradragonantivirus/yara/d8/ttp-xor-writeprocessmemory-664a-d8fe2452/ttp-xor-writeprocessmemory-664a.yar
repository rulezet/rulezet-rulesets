rule TTP_XOR_WriteProcessMemory_664a {
  strings:
    $key_664a = { 31 38 [2] 03 1a [2] 05 2f [2] 2b 2f [2] 14 33 }

  condition:
    any of them
}