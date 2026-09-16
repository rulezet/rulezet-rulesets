rule TTP_XOR_WriteProcessMemory_7c0d {
  strings:
    $key_7c0d = { 2b 7f [2] 19 5d [2] 1f 68 [2] 31 68 [2] 0e 74 }

  condition:
    any of them
}