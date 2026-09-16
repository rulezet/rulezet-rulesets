rule TTP_XOR_WriteProcessMemory_1f0f {
  strings:
    $key_1f0f = { 48 7d [2] 7a 5f [2] 7c 6a [2] 52 6a [2] 6d 76 }

  condition:
    any of them
}