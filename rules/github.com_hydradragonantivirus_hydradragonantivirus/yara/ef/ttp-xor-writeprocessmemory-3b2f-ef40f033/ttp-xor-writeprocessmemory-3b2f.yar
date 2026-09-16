rule TTP_XOR_WriteProcessMemory_3b2f {
  strings:
    $key_3b2f = { 6c 5d [2] 5e 7f [2] 58 4a [2] 76 4a [2] 49 56 }

  condition:
    any of them
}