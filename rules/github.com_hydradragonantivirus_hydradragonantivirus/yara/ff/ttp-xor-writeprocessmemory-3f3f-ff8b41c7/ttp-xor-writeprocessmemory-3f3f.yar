rule TTP_XOR_WriteProcessMemory_3f3f {
  strings:
    $key_3f3f = { 68 4d [2] 5a 6f [2] 5c 5a [2] 72 5a [2] 4d 46 }

  condition:
    any of them
}