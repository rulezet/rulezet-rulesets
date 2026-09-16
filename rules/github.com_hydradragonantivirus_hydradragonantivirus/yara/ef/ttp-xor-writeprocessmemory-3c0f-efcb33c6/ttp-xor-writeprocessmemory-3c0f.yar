rule TTP_XOR_WriteProcessMemory_3c0f {
  strings:
    $key_3c0f = { 6b 7d [2] 59 5f [2] 5f 6a [2] 71 6a [2] 4e 76 }

  condition:
    any of them
}