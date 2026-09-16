rule TTP_XOR_WriteProcessMemory_140f {
  strings:
    $key_140f = { 43 7d [2] 71 5f [2] 77 6a [2] 59 6a [2] 66 76 }

  condition:
    any of them
}