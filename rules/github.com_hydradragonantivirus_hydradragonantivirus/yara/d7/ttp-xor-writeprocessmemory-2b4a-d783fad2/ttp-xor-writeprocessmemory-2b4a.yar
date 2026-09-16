rule TTP_XOR_WriteProcessMemory_2b4a {
  strings:
    $key_2b4a = { 7c 38 [2] 4e 1a [2] 48 2f [2] 66 2f [2] 59 33 }

  condition:
    any of them
}