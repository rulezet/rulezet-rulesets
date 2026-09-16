rule TTP_XOR_WriteProcessMemory_011a {
  strings:
    $key_011a = { 56 68 [2] 64 4a [2] 62 7f [2] 4c 7f [2] 73 63 }

  condition:
    any of them
}