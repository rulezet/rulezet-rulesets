rule TTP_XOR_WriteProcessMemory_170a {
  strings:
    $key_170a = { 40 78 [2] 72 5a [2] 74 6f [2] 5a 6f [2] 65 73 }

  condition:
    any of them
}