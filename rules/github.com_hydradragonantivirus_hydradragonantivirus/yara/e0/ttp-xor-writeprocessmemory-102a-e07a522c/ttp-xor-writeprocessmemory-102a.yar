rule TTP_XOR_WriteProcessMemory_102a {
  strings:
    $key_102a = { 47 58 [2] 75 7a [2] 73 4f [2] 5d 4f [2] 62 53 }

  condition:
    any of them
}