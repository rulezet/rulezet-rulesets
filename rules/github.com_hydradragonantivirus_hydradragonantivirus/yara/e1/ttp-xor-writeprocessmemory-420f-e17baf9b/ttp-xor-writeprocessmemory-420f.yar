rule TTP_XOR_WriteProcessMemory_420f {
  strings:
    $key_420f = { 15 7d [2] 27 5f [2] 21 6a [2] 0f 6a [2] 30 76 }

  condition:
    any of them
}