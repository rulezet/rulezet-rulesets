rule TTP_XOR_WriteProcessMemory_563a {
  strings:
    $key_563a = { 01 48 [2] 33 6a [2] 35 5f [2] 1b 5f [2] 24 43 }

  condition:
    any of them
}