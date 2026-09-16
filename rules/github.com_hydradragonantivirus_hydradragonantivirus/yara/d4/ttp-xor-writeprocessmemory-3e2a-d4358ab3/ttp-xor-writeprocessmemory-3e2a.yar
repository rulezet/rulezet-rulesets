rule TTP_XOR_WriteProcessMemory_3e2a {
  strings:
    $key_3e2a = { 69 58 [2] 5b 7a [2] 5d 4f [2] 73 4f [2] 4c 53 }

  condition:
    any of them
}