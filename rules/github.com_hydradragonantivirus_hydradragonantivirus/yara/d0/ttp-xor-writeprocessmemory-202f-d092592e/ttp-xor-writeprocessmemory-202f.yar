rule TTP_XOR_WriteProcessMemory_202f {
  strings:
    $key_202f = { 77 5d [2] 45 7f [2] 43 4a [2] 6d 4a [2] 52 56 }

  condition:
    any of them
}