rule TTP_XOR_WriteProcessMemory_081a {
  strings:
    $key_081a = { 5f 68 [2] 6d 4a [2] 6b 7f [2] 45 7f [2] 7a 63 }

  condition:
    any of them
}