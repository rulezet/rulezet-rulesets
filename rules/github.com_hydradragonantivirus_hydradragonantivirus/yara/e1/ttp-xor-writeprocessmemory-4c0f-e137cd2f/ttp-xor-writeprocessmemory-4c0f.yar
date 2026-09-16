rule TTP_XOR_WriteProcessMemory_4c0f {
  strings:
    $key_4c0f = { 1b 7d [2] 29 5f [2] 2f 6a [2] 01 6a [2] 3e 76 }

  condition:
    any of them
}