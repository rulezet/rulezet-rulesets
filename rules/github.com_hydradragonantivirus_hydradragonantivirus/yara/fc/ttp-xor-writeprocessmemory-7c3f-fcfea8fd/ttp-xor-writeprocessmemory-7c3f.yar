rule TTP_XOR_WriteProcessMemory_7c3f {
  strings:
    $key_7c3f = { 2b 4d [2] 19 6f [2] 1f 5a [2] 31 5a [2] 0e 46 }

  condition:
    any of them
}