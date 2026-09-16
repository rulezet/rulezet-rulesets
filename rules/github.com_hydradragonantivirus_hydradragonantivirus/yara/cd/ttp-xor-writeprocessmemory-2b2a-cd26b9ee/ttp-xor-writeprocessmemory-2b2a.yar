rule TTP_XOR_WriteProcessMemory_2b2a {
  strings:
    $key_2b2a = { 7c 58 [2] 4e 7a [2] 48 4f [2] 66 4f [2] 59 53 }

  condition:
    any of them
}