rule TTP_XOR_WriteProcessMemory_290a {
  strings:
    $key_290a = { 7e 78 [2] 4c 5a [2] 4a 6f [2] 64 6f [2] 5b 73 }

  condition:
    any of them
}