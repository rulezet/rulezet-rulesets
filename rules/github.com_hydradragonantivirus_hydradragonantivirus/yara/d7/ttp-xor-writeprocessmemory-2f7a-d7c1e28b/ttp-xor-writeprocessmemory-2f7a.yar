rule TTP_XOR_WriteProcessMemory_2f7a {
  strings:
    $key_2f7a = { 78 08 [2] 4a 2a [2] 4c 1f [2] 62 1f [2] 5d 03 }

  condition:
    any of them
}