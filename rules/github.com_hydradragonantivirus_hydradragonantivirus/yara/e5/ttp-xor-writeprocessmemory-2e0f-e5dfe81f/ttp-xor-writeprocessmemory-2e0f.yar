rule TTP_XOR_WriteProcessMemory_2e0f {
  strings:
    $key_2e0f = { 79 7d [2] 4b 5f [2] 4d 6a [2] 63 6a [2] 5c 76 }

  condition:
    any of them
}