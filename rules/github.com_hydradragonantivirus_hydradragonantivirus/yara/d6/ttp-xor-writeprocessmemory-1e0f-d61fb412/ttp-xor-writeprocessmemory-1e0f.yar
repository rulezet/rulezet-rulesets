rule TTP_XOR_WriteProcessMemory_1e0f {
  strings:
    $key_1e0f = { 49 7d [2] 7b 5f [2] 7d 6a [2] 53 6a [2] 6c 76 }

  condition:
    any of them
}