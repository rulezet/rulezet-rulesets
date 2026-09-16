rule TTP_XOR_WriteProcessMemory_510f {
  strings:
    $key_510f = { 06 7d [2] 34 5f [2] 32 6a [2] 1c 6a [2] 23 76 }

  condition:
    any of them
}