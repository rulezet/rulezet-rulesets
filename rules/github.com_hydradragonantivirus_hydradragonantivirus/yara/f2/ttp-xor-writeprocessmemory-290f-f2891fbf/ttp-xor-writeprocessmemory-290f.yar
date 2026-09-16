rule TTP_XOR_WriteProcessMemory_290f {
  strings:
    $key_290f = { 7e 7d [2] 4c 5f [2] 4a 6a [2] 64 6a [2] 5b 76 }

  condition:
    any of them
}