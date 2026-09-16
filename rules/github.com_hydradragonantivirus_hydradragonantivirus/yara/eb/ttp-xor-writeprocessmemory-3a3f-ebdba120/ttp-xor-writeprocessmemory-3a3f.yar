rule TTP_XOR_WriteProcessMemory_3a3f {
  strings:
    $key_3a3f = { 6d 4d [2] 5f 6f [2] 59 5a [2] 77 5a [2] 48 46 }

  condition:
    any of them
}