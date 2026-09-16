rule TTP_XOR_WriteProcessMemory_287a {
  strings:
    $key_287a = { 7f 08 [2] 4d 2a [2] 4b 1f [2] 65 1f [2] 5a 03 }

  condition:
    any of them
}