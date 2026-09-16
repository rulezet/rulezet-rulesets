rule TTP_XOR_WriteProcessMemory_2f2a {
  strings:
    $key_2f2a = { 78 58 [2] 4a 7a [2] 4c 4f [2] 62 4f [2] 5d 53 }

  condition:
    any of them
}