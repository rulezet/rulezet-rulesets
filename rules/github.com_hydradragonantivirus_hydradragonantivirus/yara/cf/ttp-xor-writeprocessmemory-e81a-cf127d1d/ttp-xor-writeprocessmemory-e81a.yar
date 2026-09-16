rule TTP_XOR_WriteProcessMemory_e81a {
  strings:
    $key_e81a = { bf 68 [2] 8d 4a [2] 8b 7f [2] a5 7f [2] 9a 63 }

  condition:
    any of them
}