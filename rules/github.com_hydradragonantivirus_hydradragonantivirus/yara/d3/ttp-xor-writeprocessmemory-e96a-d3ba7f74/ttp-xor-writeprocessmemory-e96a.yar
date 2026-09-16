rule TTP_XOR_WriteProcessMemory_e96a {
  strings:
    $key_e96a = { be 18 [2] 8c 3a [2] 8a 0f [2] a4 0f [2] 9b 13 }

  condition:
    any of them
}