rule TTP_XOR_WriteProcessMemory_431a {
  strings:
    $key_431a = { 14 68 [2] 26 4a [2] 20 7f [2] 0e 7f [2] 31 63 }

  condition:
    any of them
}