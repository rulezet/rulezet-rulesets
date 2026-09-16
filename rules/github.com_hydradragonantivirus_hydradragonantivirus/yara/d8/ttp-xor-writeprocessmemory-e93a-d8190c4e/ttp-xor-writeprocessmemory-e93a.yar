rule TTP_XOR_WriteProcessMemory_e93a {
  strings:
    $key_e93a = { be 48 [2] 8c 6a [2] 8a 5f [2] a4 5f [2] 9b 43 }

  condition:
    any of them
}