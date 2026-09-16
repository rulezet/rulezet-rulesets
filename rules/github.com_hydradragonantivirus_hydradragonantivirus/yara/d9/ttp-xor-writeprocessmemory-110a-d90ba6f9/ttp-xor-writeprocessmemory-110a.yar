rule TTP_XOR_WriteProcessMemory_110a {
  strings:
    $key_110a = { 46 78 [2] 74 5a [2] 72 6f [2] 5c 6f [2] 63 73 }

  condition:
    any of them
}