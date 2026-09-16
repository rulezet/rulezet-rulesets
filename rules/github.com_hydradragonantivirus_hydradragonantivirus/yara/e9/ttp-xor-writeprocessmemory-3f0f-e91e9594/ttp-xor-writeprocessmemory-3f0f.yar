rule TTP_XOR_WriteProcessMemory_3f0f {
  strings:
    $key_3f0f = { 68 7d [2] 5a 5f [2] 5c 6a [2] 72 6a [2] 4d 76 }

  condition:
    any of them
}