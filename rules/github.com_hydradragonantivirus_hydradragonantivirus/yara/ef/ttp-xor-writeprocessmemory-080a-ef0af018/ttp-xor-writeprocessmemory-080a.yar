rule TTP_XOR_WriteProcessMemory_080a {
  strings:
    $key_080a = { 5f 78 [2] 6d 5a [2] 6b 6f [2] 45 6f [2] 7a 73 }

  condition:
    any of them
}