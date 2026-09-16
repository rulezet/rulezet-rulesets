rule TTP_XOR_WriteProcessMemory_2b7a {
  strings:
    $key_2b7a = { 7c 08 [2] 4e 2a [2] 48 1f [2] 66 1f [2] 59 03 }

  condition:
    any of them
}