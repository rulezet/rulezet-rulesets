rule TTP_XOR_WriteProcessMemory_7d2f {
  strings:
    $key_7d2f = { 2a 5d [2] 18 7f [2] 1e 4a [2] 30 4a [2] 0f 56 }

  condition:
    any of them
}